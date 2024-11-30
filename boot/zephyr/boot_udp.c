#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>
#include <bootutil/bootutil_log.h>
#include <bootutil/image.h>
#include <bootutil/boot_hooks.h>
#include <src/bootutil_priv.h>
#include <zcbor_encode.h>
#include <zcbor_decode.h>
#include <io/io.h>

BOOT_LOG_MODULE_REGISTER(mcuboot_udp);

#define MGMT_ERR_OK 0
#define MGMT_ERR_EUNKNOWN 1
#define MGMT_ERR_ENOMEM 2
#define MGMT_ERR_EINVAL 3
#define MGMT_ERR_ENOENT 5
#define MGMT_ERR_ENOTSUP 8
#define MGMT_ERR_EBUSY 10

#define NMGR_OP_READ 0
#define NMGR_OP_WRITE 2

#define MGMT_GROUP_ID_OS 0
#define MGMT_GROUP_ID_IMAGE 1
#define MGMT_GROUP_ID_PERUSER 64

#define NMGR_ID_RESET 5
#define NMGR_ID_PARAMS 6

#define NMGR_ID_STATE 0
#define NMGR_ID_UPLOAD 1
#define NMGR_ID_SLOT_INFO 6

#if defined(MCUBOOT_SHA512)
#define IMAGE_HASH_SIZE (64)
#define IMAGE_SHA_TLV IMAGE_TLV_SHA512
#elif defined(MCUBOOT_SIGN_EC384)
#define IMAGE_HASH_SIZE (48)
#define IMAGE_SHA_TLV IMAGE_TLV_SHA384
#else
#define IMAGE_HASH_SIZE (32)
#define IMAGE_SHA_TLV IMAGE_TLV_SHA256
#endif

#define CBOR_ENTRIES_SLOT_INFO_IMAGE_MAP 4
#define CBOR_ENTRIES_SLOT_INFO_SLOTS_MAP 3

#define KEY_FILTER(k, val) (k.len == strlen(val) && memcmp(k.value, val, key.len) == 0)
static int sock;

struct nmgr_hdr {
	uint8_t nh_op : 3;
	uint8_t nh_version : 2;
	uint8_t _res1 : 3;
	uint8_t nh_flags;
	uint16_t nh_len;
	uint16_t nh_group;
	uint8_t nh_seq;
	uint8_t nh_id;
} __packed;

static zcbor_state_t cbor_state[2];
static uint8_t udp_buffer[2048];
static uint8_t bs_obuf[1024];
static struct sockaddr_in client_addr;
static socklen_t addrlen;

static void bs_list_img_ver(char *dst, int maxlen, struct image_version *ver)
{
	int len;

	len = snprintf(dst, maxlen, "%hu.%hu.%hu", (uint16_t)ver->iv_major,
		       (uint16_t)ver->iv_minor, ver->iv_revision);
	if (ver->iv_build_num != 0 && len > 0 && len < maxlen) {
		snprintf(&dst[len], (maxlen - len), ".%u", ver->iv_build_num);
	}
}

static void reset_cbor_state(void)
{
	zcbor_new_encode_state(cbor_state, 2, bs_obuf, sizeof(bs_obuf), 0);
}

static int boot_serial_get_hash(const struct image_header *hdr,
				const struct flash_area *fap, uint8_t *hash)
{
	struct image_tlv_iter it;
	uint32_t offset;
	uint16_t len;
	uint16_t type;
	int rc;

	/* Manifest data is concatenated to the end of the image. It is encoded in TLV format. */
	rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_ANY, false);
	if (rc) {
		return -1;
	}

	/* Traverse through the TLV area to find the image hash TLV. */
	while (true) {
		rc = bootutil_tlv_iter_next(&it, &offset, &len, &type);
		if (rc < 0) {
			return -1;
		} else if (rc > 0) {
			break;
		}
		if (type == IMAGE_SHA_TLV) {
			/* Get the image's hash value from the manifest section. */
			if (len != IMAGE_HASH_SIZE) {
				return -1;
			}
			rc = flash_area_read(fap, offset, hash, len);
			if (rc) {
				return -1;
			}
			return 0;
		}
	}

	return -1;
}

static void boot_grp_send(void)
{
	struct nmgr_hdr *hdr;

	int len = (uintptr_t)cbor_state->payload_mut - (uintptr_t)bs_obuf;
	hdr = (struct nmgr_hdr *)udp_buffer;
	hdr->nh_len = htons(len);
	hdr->nh_group = htons(hdr->nh_group);
	memcpy(udp_buffer + sizeof(*hdr), bs_obuf, len);
	len += sizeof(*hdr);
	zsock_sendto(sock, udp_buffer, len, 0, (struct sockaddr *)&client_addr, addrlen);
}

static void bs_rc_rsp(int rc_code)
{
	zcbor_map_start_encode(cbor_state, 10);
	zcbor_tstr_put_lit(cbor_state, "rc");
	zcbor_int32_put(cbor_state, rc_code);
	zcbor_map_end_encode(cbor_state, 10);
	boot_grp_send();
}

static void bs_list(char *buf, int len)
{
	struct image_header hdr;
	uint32_t slot, area_id;
	const struct flash_area *fap;
	uint8_t image_index;
	uint8_t hash[IMAGE_HASH_SIZE];

	zcbor_map_start_encode(cbor_state, 1);
	zcbor_tstr_put_lit(cbor_state, "images");
	zcbor_list_start_encode(cbor_state, 5);

	image_index = 0;
	int swap_status = boot_swap_type_multi(image_index);
	for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
		FIH_DECLARE(fih_rc, FIH_FAILURE);
		uint8_t tmpbuf[64];
		bool active = false;
		bool confirmed = false;
		bool pending = false;
		bool permanent = false;
		area_id = flash_area_id_from_multi_image_slot(image_index, slot);
		if (flash_area_open(area_id, &fap)) {
			continue;
		}
		int rc = BOOT_HOOK_CALL(boot_read_image_header_hook,
					BOOT_HOOK_REGULAR, image_index, slot,
					&hdr);
		if (rc == BOOT_HOOK_REGULAR) {
			flash_area_read(fap, 0, &hdr, sizeof(hdr));
		}
		if (hdr.ih_magic == IMAGE_MAGIC) {
			BOOT_HOOK_CALL_FIH(boot_image_check_hook,
					   FIH_BOOT_HOOK_REGULAR, fih_rc,
					   image_index, slot);
			if (FIH_EQ(fih_rc, FIH_BOOT_HOOK_REGULAR)) {
				FIH_CALL(bootutil_img_validate, fih_rc, NULL, 0,
					 &hdr, fap, tmpbuf, sizeof(tmpbuf),
					 NULL, 0, NULL);
			}
		}
		if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
			flash_area_close(fap);
			continue;
		}
		/* Retrieve hash of image for identification */
		rc = boot_serial_get_hash(&hdr, fap, hash);
		flash_area_close(fap);
		zcbor_map_start_encode(cbor_state, 20);
		if (swap_status == BOOT_SWAP_TYPE_NONE) {
			if (slot == BOOT_PRIMARY_SLOT) {
				confirmed = true;
				active = true;
			}
		} else if (swap_status == BOOT_SWAP_TYPE_TEST) {
			if (slot == BOOT_PRIMARY_SLOT) {
				confirmed = true;
			} else {
				pending = true;
			}
		} else if (swap_status == BOOT_SWAP_TYPE_PERM) {
			if (slot == BOOT_PRIMARY_SLOT) {
				confirmed = true;
			} else {
				pending = true;
				permanent = true;
			}
		} else if (swap_status == BOOT_SWAP_TYPE_REVERT) {
			if (slot == BOOT_PRIMARY_SLOT) {
				active = true;
			} else {
				confirmed = true;
			}
		}
		if (!(hdr.ih_flags & IMAGE_F_NON_BOOTABLE)) {
			zcbor_tstr_put_lit(cbor_state, "bootable");
			zcbor_bool_put(cbor_state, true);
		}
		if (confirmed) {
			zcbor_tstr_put_lit(cbor_state, "confirmed");
			zcbor_bool_put(cbor_state, true);
		}
		if (active) {
			zcbor_tstr_put_lit(cbor_state, "active");
			zcbor_bool_put(cbor_state, true);
		}
		if (pending) {
			zcbor_tstr_put_lit(cbor_state, "pending");
			zcbor_bool_put(cbor_state, true);
		}
		if (permanent) {
			zcbor_tstr_put_lit(cbor_state, "permanent");
			zcbor_bool_put(cbor_state, true);
		}
		zcbor_tstr_put_lit(cbor_state, "slot");
		zcbor_uint32_put(cbor_state, slot);
		if (rc == 0) {
			zcbor_tstr_put_lit(cbor_state, "hash");
			zcbor_bstr_encode_ptr(cbor_state, hash, sizeof(hash));
		}
		zcbor_tstr_put_lit(cbor_state, "version");
		bs_list_img_ver((char *)tmpbuf, sizeof(tmpbuf), &hdr.ih_ver);
		zcbor_tstr_encode_ptr(cbor_state, (char *)tmpbuf,
				      strlen((char *)tmpbuf));
		zcbor_map_end_encode(cbor_state, 20);
	}
	zcbor_list_end_encode(cbor_state, 5);
	zcbor_map_end_encode(cbor_state, 1);
	boot_grp_send();
}

static void bs_set(char *buf, int len)
{
	uint8_t image_index = 0;
	uint8_t hash[IMAGE_HASH_SIZE];
	bool confirm;
	struct zcbor_string img_hash, key;
	bool ok;
	int rc;
	bool found = false;

	ZCBOR_STATE_D(zsd, 2, (uint8_t *)buf, len, 1, 0);
	ok = zcbor_map_start_decode(zsd);
	if (!ok) {
		rc = MGMT_ERR_EINVAL;
		goto out;
	}
	while (ok) {
		ok = zcbor_tstr_decode(zsd, &key);
		if (ok && KEY_FILTER(key, "confirm"))
			zcbor_bool_decode(zsd, &confirm);
		else if (ok && KEY_FILTER(key, "hash"))
			zcbor_bstr_decode(zsd, &img_hash);
		else
			zcbor_any_skip(zsd, NULL);
	}
	zcbor_map_end_decode(zsd);

	if ((img_hash.len != sizeof(hash) && img_hash.len != 0) ||
	    (img_hash.len == 0 && BOOT_IMAGE_NUMBER > 1)) {
		/* Hash is required and was not provided or is invalid size */
		rc = MGMT_ERR_EINVAL;
		goto out;
	}
	if (img_hash.len != 0) {
		for (image_index = 0; image_index < BOOT_IMAGE_NUMBER; ++image_index) {
			struct image_header hdr;
			uint32_t area_id;
			const struct flash_area *fap;
			uint8_t tmpbuf[64];
			area_id = flash_area_id_from_multi_image_slot( image_index, 1);
			if (flash_area_open(area_id, &fap)) {
				BOOT_LOG_ERR("Failed to open flash area ID %d",
					     area_id);
				continue;
			}
			rc = BOOT_HOOK_CALL(boot_read_image_header_hook,
					    BOOT_HOOK_REGULAR, image_index, 1,
					    &hdr);
			if (rc == BOOT_HOOK_REGULAR) {
				flash_area_read(fap, 0, &hdr, sizeof(hdr));
			}
			if (hdr.ih_magic == IMAGE_MAGIC) {
				FIH_DECLARE(fih_rc, FIH_FAILURE);
				BOOT_HOOK_CALL_FIH(boot_image_check_hook,
						   FIH_BOOT_HOOK_REGULAR,
						   fih_rc, image_index, 1);
				if (FIH_EQ(fih_rc, FIH_BOOT_HOOK_REGULAR)) {
					FIH_CALL(bootutil_img_validate, fih_rc,
						 NULL, 0, &hdr, fap, tmpbuf,
						 sizeof(tmpbuf), NULL, 0, NULL);
				}
				if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
					continue;
				}
			}
			/* Retrieve hash of image for identification */
			rc = boot_serial_get_hash(&hdr, fap, hash);
			flash_area_close(fap);
			if (rc == 0 && memcmp(hash, img_hash.value, sizeof(hash)) == 0) {
				/* Hash matches, set this slot for test or confirmation */
				found = true;
				break;
			}
		}
		if (!found) {
			/* Image was not found with specified hash */
			BOOT_LOG_ERR("Did not find image with specified hash");
			rc = MGMT_ERR_ENOENT;
			goto out;
		}
	}
	rc = boot_set_pending_multi(image_index, confirm);
out:
	if (rc == 0) {
		/* Success - return updated list of images */
		bs_list(buf, len);
	} else {
		/* Error code, only return the error */
		zcbor_map_start_encode(cbor_state, 10);
		zcbor_tstr_put_lit(cbor_state, "rc");
		zcbor_int32_put(cbor_state, rc);
		zcbor_map_end_encode(cbor_state, 10);
		boot_grp_send();
	}
}

static void bs_list_set(uint8_t op, char *buf, int len)
{
	if (op == NMGR_OP_READ) {
		bs_list(buf, len);
	} else {
		bs_set(buf, len);
	}
}

static void proccess_bar_print(const char *title, int idx, int total)
{
	char sbuf[256];
	int offset = 0;

	offset = snprintf(sbuf, sizeof(sbuf), "%s: [", title);
	memset(sbuf + offset, '#', idx);
	offset += idx;
	if (idx != total) {
		memset(sbuf + offset, ' ', total - idx);
		offset += total - idx;
	}
	offset = snprintf(sbuf + offset, sizeof(sbuf) - offset, "] %d/100%c",
			  idx, idx == total ? '\n' : '\r');
	printf("%s", sbuf);
#ifdef CONFIG_MCUBOOT_INDICATION_LED
    io_led_set((idx+1)%2);
#endif
}

static void bs_upload(char *buf, int len)
{
	static size_t img_size;
	static uint32_t curr_off;
	const uint8_t *img_chunk = NULL;
	size_t img_chunk_len = 0;
	size_t img_chunk_off = SIZE_MAX;
	size_t rem_bytes;
	uint32_t img_num_tmp = UINT_MAX;
	static uint32_t img_num = 0;
	size_t img_size_tmp = SIZE_MAX;
	const struct flash_area *fap = NULL;
	int rc;
	struct zcbor_string img_chunk_data, key;
	bool ok;

	ZCBOR_STATE_D(zsd, 2, (uint8_t *)buf, len, 1, 0);
	ok = zcbor_map_start_decode(zsd);
	if (!ok) {
		rc = MGMT_ERR_EINVAL;
		goto out;
	}
	while (ok) {
		ok = zcbor_tstr_decode(zsd, &key);
		if (ok && KEY_FILTER(key, "image"))
			zcbor_uint32_decode(zsd, &img_num_tmp);
		else if (ok && KEY_FILTER(key, "data"))
			zcbor_bstr_decode(zsd, &img_chunk_data);
		else if (ok && KEY_FILTER(key, "len"))
			zcbor_size_decode(zsd, &img_size_tmp);
		else if (ok && KEY_FILTER(key, "off"))
			zcbor_size_decode(zsd, &img_chunk_off);
		else
			zcbor_any_skip(zsd, NULL);
	}
	zcbor_map_end_decode(zsd);


	img_chunk = img_chunk_data.value;
	img_chunk_len = img_chunk_data.len;
	if (img_chunk_off == SIZE_MAX || img_chunk == NULL) {
		goto out_invalid_data;
	}
	if (img_chunk_off == 0) {
		if (img_num_tmp != UINT_MAX) {
			img_num = img_num_tmp;
		} else {
			img_num = 0;
		}
	}
	rc = flash_area_open(flash_area_id_from_multi_image_slot(img_num, 1), &fap);
	if (rc) {
		rc = MGMT_ERR_EINVAL;
		goto out;
	}
	if (img_chunk_off == 0) {
		const size_t area_size = flash_area_get_size(fap);
		curr_off = 0;
		if (img_size_tmp > area_size) {
			goto out_invalid_data;
		}
		rc = flash_area_erase(fap, 0, area_size);
		if (rc) {
			goto out_invalid_data;
		}
		img_size = img_size_tmp;
	} else if (img_chunk_off != curr_off) {
		rc = 0;
		goto out;
	} else if (curr_off + img_chunk_len > img_size) {
		rc = MGMT_ERR_EINVAL;
		goto out;
	}
	rem_bytes = img_chunk_len % flash_area_align(fap);
	img_chunk_len -= rem_bytes;
	if (curr_off + img_chunk_len + rem_bytes < img_size) {
		rem_bytes = 0;
	}
	BOOT_LOG_DBG("Writing at 0x%x until 0x%x", curr_off, curr_off + (uint32_t)img_chunk_len);
	int idx_old = curr_off * 100 / img_size;
	int idx = (curr_off + (uint32_t)img_chunk_len) * 100 / img_size;
	if (idx_old != idx)
		proccess_bar_print("Firmware upgrade proccess", idx, 100);
	rc = flash_area_write(fap, curr_off, img_chunk, img_chunk_len);
	if (rc == 0 && rem_bytes) {
		uint8_t wbs_aligned[BOOT_MAX_ALIGN];
		memset(wbs_aligned, flash_area_erased_val(fap),
		       sizeof(wbs_aligned));
		memcpy(wbs_aligned, img_chunk + img_chunk_len, rem_bytes);
		rc = flash_area_write(fap, curr_off + img_chunk_len,
				      wbs_aligned, flash_area_align(fap));
	}
	if (rc == 0) {
		curr_off += img_chunk_len + rem_bytes;
		if (curr_off == img_size) {
			rc = BOOT_HOOK_CALL(boot_serial_uploaded_hook, 0,
					    img_num, fap, img_size);
			if (rc) {
				BOOT_LOG_ERR("Error %d post upload hook", rc);
				goto out;
			}
		rc = boot_set_pending_multi(0, true);
		}
	} else {
out_invalid_data:
		rc = MGMT_ERR_EINVAL;
	}
out:
	BOOT_LOG_DBG("RX: 0x%x", rc);
	zcbor_map_start_encode(cbor_state, 10);
	zcbor_tstr_put_lit(cbor_state, "rc");
	zcbor_int32_put(cbor_state, rc);
	if (rc == 0) {
		zcbor_tstr_put_lit(cbor_state, "off");
		zcbor_uint32_put(cbor_state, curr_off);
	}
	zcbor_map_end_encode(cbor_state, 10);
	boot_grp_send();
	flash_area_close(fap);
}

static void bs_slot_info(uint8_t op, char *buf, int len)
{
	uint32_t slot, area_id;
	const struct flash_area *fap;
	uint8_t image_index = 0;
	int rc;
	bool ok = true;

	if (op != NMGR_OP_READ) {
		bs_rc_rsp(MGMT_ERR_ENOTSUP);
		return;
	}
	zcbor_map_start_encode(cbor_state, 1);
	zcbor_tstr_put_lit(cbor_state, "images");
	zcbor_list_start_encode(cbor_state, MCUBOOT_IMAGE_NUMBER);
	for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
		if (slot == 0) {
			ok = zcbor_map_start_encode(cbor_state, CBOR_ENTRIES_SLOT_INFO_IMAGE_MAP) &&
			     zcbor_tstr_put_lit(cbor_state, "image") &&
			     zcbor_uint32_put(cbor_state, (uint32_t)image_index) &&
			     zcbor_tstr_put_lit(cbor_state, "slots") &&
			     zcbor_list_start_encode(cbor_state, BOOT_NUM_SLOTS);
			if (!ok) {
				goto finish;
			}
		}
		ok = zcbor_map_start_encode(cbor_state, CBOR_ENTRIES_SLOT_INFO_SLOTS_MAP) &&
		     zcbor_tstr_put_lit(cbor_state, "slot") &&
		     zcbor_uint32_put(cbor_state, slot);
		if (!ok) {
			goto finish;
		}
		area_id = flash_area_id_from_multi_image_slot(image_index, slot);
		rc = flash_area_open(area_id, &fap);
		if (rc) {
			ok = zcbor_tstr_put_lit(cbor_state, "rc") &&
			     zcbor_int32_put(cbor_state, rc);
		} else {
			if (sizeof(fap->fa_size) == sizeof(uint64_t)) {
				ok = zcbor_tstr_put_lit(cbor_state, "size") &&
				     zcbor_uint64_put(cbor_state, fap->fa_size);
			} else {
				ok = zcbor_tstr_put_lit(cbor_state, "size") &&
				     zcbor_uint32_put(cbor_state, fap->fa_size);
			}
			if (!ok) {
				flash_area_close(fap);
				goto finish;
			}
			if (slot == 1) {
				ok = zcbor_tstr_put_lit(cbor_state, "upload_image_id") &&
				     zcbor_uint32_put(cbor_state, (image_index * 2 + 1));
			}
			flash_area_close(fap);
			if (!ok) {
				goto finish;
			}
			ok = zcbor_map_end_encode(cbor_state, CBOR_ENTRIES_SLOT_INFO_SLOTS_MAP);
			if (!ok) {
				goto finish;
			}
			if (slot == (BOOT_NUM_SLOTS - 1)) {
				ok = zcbor_list_end_encode(cbor_state, BOOT_NUM_SLOTS);
				if (!ok) {
					goto finish;
				}
				ok = zcbor_map_end_encode(cbor_state, CBOR_ENTRIES_SLOT_INFO_IMAGE_MAP);
			}
		}
		if (!ok) {
			goto finish;
		}
	}
	ok = zcbor_list_end_encode(cbor_state, MCUBOOT_IMAGE_NUMBER) &&
	     zcbor_map_end_encode(cbor_state, 1);
finish:
	if (!ok) {
		reset_cbor_state();
		bs_rc_rsp(MGMT_ERR_ENOMEM);
		return;
	}
	boot_grp_send();
}

static void bs_reset(const char *buf, int len)
{
	struct nmgr_hdr *hdr;

	hdr = (struct nmgr_hdr *)udp_buffer;
	hdr->nh_len = 0;
	hdr->nh_group = htons(hdr->nh_group);
	zsock_sendto(sock, udp_buffer, sizeof(*hdr), 0,
		     (struct sockaddr *)&client_addr, addrlen);
	k_msleep(250);
	sys_reboot(SYS_REBOOT_COLD);
}

static void bs_params(uint8_t op, const char *buf, int len)
{
	if (op != NMGR_OP_READ) {
		bs_rc_rsp(MGMT_ERR_ENOTSUP);
		return;
	}
	zcbor_map_start_encode(cbor_state, 10);
	zcbor_tstr_put_lit(cbor_state, "buf_size");
	zcbor_uint32_put(cbor_state, sizeof(udp_buffer));
	zcbor_tstr_put_lit(cbor_state, "buf_count");
	zcbor_uint32_put(cbor_state, 1);
	zcbor_map_end_encode(cbor_state, 10);
	boot_grp_send();
}

static void boot_grp_procces(uint8_t *buf, size_t len)
{
	struct nmgr_hdr *hdr;

	hdr = (struct nmgr_hdr *)buf;
	if (len < sizeof(*hdr) ||
	    (hdr->nh_op != NMGR_OP_READ && hdr->nh_op != NMGR_OP_WRITE) ||
	    (ntohs(hdr->nh_len) < len - sizeof(*hdr))) {
		return;
	}

	hdr->nh_group = ntohs(hdr->nh_group);
	buf += sizeof(*hdr);
	len -= sizeof(*hdr);

	reset_cbor_state();
	switch (hdr->nh_group) {
	case MGMT_GROUP_ID_IMAGE:
		switch (hdr->nh_id) {
		case NMGR_ID_STATE:
			bs_list_set(hdr->nh_op, buf, len);
			break;
		case NMGR_ID_UPLOAD:
			bs_upload(buf, len);
			break;
		case NMGR_ID_SLOT_INFO:
			bs_slot_info(hdr->nh_op, buf, len);
			break;
		default:
			bs_rc_rsp(MGMT_ERR_ENOTSUP);
			BOOT_LOG_WRN("group:%d, id: %d not support",
				     hdr->nh_group, hdr->nh_id);
		}
		break;
	case MGMT_GROUP_ID_OS:
		switch (hdr->nh_id) {
		case NMGR_ID_RESET:
			bs_reset(buf, len);
			break;
		case NMGR_ID_PARAMS:
			bs_params(hdr->nh_op, buf, len);
			break;
		default:
			bs_rc_rsp(MGMT_ERR_ENOTSUP);
			BOOT_LOG_WRN("group:%d, id: %d not support",
				     hdr->nh_group, hdr->nh_id);
		}
		break;
	default:
		bs_rc_rsp(MGMT_ERR_ENOTSUP);
		BOOT_LOG_WRN("group:%d not support", hdr->nh_group);
		break;
	};
}

int boot_udp_init(void)
{
#ifdef CONFIG_MCUBOOT_UDP_IP_ADDRESS
	struct in_addr addr, netmask;
	int count = CONFIG_UDP_LINK_COUNT;
	struct net_if *iface= net_if_get_first_by_type(&NET_L2_GET_NAME(ETHERNET));
	if (!iface) {
		BOOT_LOG_ERR("No ethernet interfaces found.");
		return -1;
	}

	while (!net_if_is_up(iface)) {
		if (count--) {
			k_msleep(100);
		} else {
			BOOT_LOG_ERR("Link not up.");
			return -1;
		}
	}

	net_addr_pton(AF_INET, CONFIG_MCUBOOT_UDP_IP_ADDRESS, &addr);
	netmask.s_addr = 0xffffff;
	if (net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0) == NULL) {
		BOOT_LOG_ERR("Cannot add ip address to interface");
		return -1;
	}
	if (net_if_ipv4_set_netmask_by_addr(iface, &addr, &netmask) == false) {
		BOOT_LOG_ERR("Cannot add netmask to interface");
		return -1;
	}
	BOOT_LOG_INF("network is linked, ip address: %s, waiting smp connect", CONFIG_MCUBOOT_UDP_IP_ADDRESS);
#endif
	int ret;
	struct sockaddr_in server_addr;

	sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		BOOT_LOG_ERR("udp socket create error");
		return -1;
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(CONFIG_MCUBOOT_UDP_PORT);
	ret = zsock_bind(sock, (struct sockaddr *)&server_addr,
			 sizeof(server_addr));
	if (ret) {
		BOOT_LOG_ERR("udp bind error");
		return -1;
	}

#ifdef CONFIG_MCUBOOT_INDICATION_LED
	io_led_set(1);
#endif
	return sock;
}

void boot_udp_start(int timeout_in_s)
{
	struct timeval optval = {
		.tv_sec = timeout_in_s,
		.tv_usec = 0,
	};

	int ret = zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &optval, sizeof(optval));
	if (ret) {
		BOOT_LOG_ERR("set SO_RCVTIMEO failed: %d", ret);
		zsock_close(sock);
		return;
	}
	while (1) {
		addrlen = sizeof(client_addr);
		ret = zsock_recvfrom(sock, udp_buffer, sizeof(udp_buffer), 0,
				     (struct sockaddr *)&client_addr, &addrlen);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				BOOT_LOG_INF(
					"No udp packet received, booting...");
				zsock_close(sock);
#ifdef CONFIG_MCUBOOT_INDICATION_LED
				io_led_set(0);
#endif
				return;
			} else {
				BOOT_LOG_ERR("Error receiving data: %d", errno);
			}
		} else {
			boot_grp_procces(udp_buffer, ret);
		}
	}
}
