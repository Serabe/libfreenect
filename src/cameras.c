/*
 * This file is part of the OpenKinect Project. http://www.openkinect.org
 *
 * Copyright (c) 2010 individual OpenKinect contributors. See the CONTRIB file
 * for details.
 *
 * This code is licensed to you under the terms of the Apache License, version
 * 2.0, or, at your option, the terms of the GNU General Public License,
 * version 2.0. See the APACHE20 and GPL2 files for the text of the licenses,
 * or the following URLs:
 * http://www.apache.org/licenses/LICENSE-2.0
 * http://www.gnu.org/licenses/gpl-2.0.txt
 *
 * If you redistribute this file in source form, modified or unmodified, you
 * may:
 *   1) Leave this header intact and distribute it under the same terms,
 *      accompanying it with the APACHE20 and GPL20 files, or
 *   2) Delete the Apache 2.0 clause and accompany it with the GPL2 file, or
 *   3) Delete the GPL v2 clause and accompany it with the APACHE20 file
 * In all cases you must keep the copyright notice intact and include a copy
 * of the CONTRIB file.
 *
 * Binary distributions must follow the binary distribution requirements of
 * either License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "freenect_internal.h"

struct pkt_hdr {
	uint8_t magic[2];
	uint8_t pad;
	uint8_t flag;
	uint8_t unk1;
	uint8_t seq;
	uint8_t unk2;
	uint8_t unk3;
	uint32_t timestamp;
};

extern const struct caminit inits[];
extern const int num_inits;

static int stream_process(freenect_context *ctx, packet_stream *strm, uint8_t *pkt, int len)
{
	if (len < 12)
		return 0;

	struct pkt_hdr *hdr = (void*)pkt;
	uint8_t *data = pkt + sizeof(*hdr);
	int datalen = len - sizeof(*hdr);

	if (hdr->magic[0] != 'R' || hdr->magic[1] != 'B') {
		FN_LOG(strm->valid_frames < 2 ? LL_SPEW : LL_NOTICE, \
		       "[Stream %02x] Invalid magic %02x%02x\n", strm->flag, hdr->magic[0], hdr->magic[1]);
		return 0;
	}

	FN_FLOOD("[Stream %02x] Packet with flag: %02x\n", strm->flag, hdr->flag);

	uint8_t sof = strm->flag|1;
	uint8_t mof = strm->flag|2;
	uint8_t eof = strm->flag|5;

	// sync if required, dropping packets until SOF
	if (!strm->synced) {
		if (hdr->flag != sof) {
			FN_SPEW("[Stream %02x] Not synced yet...\n", strm->flag);
			return 0;
		}
		strm->synced = 1;
		strm->seq = hdr->seq;
		strm->pkt_num = 0;
		strm->valid_pkts = 0;
		strm->got_pkts = 0;
	}

	int got_frame = 0;

	// handle lost packets
	if (strm->seq != hdr->seq) {
		uint8_t lost = hdr->seq - strm->seq;
		FN_LOG(strm->valid_frames < 2 ? LL_SPEW : LL_INFO, \
		       "[Stream %02x] Lost %d packets\n", strm->flag, lost);
		if (lost > 5) {
			FN_LOG(strm->valid_frames < 2 ? LL_SPEW : LL_NOTICE, \
			       "[Stream %02x] Lost too many packets, resyncing...\n", strm->flag);
			strm->synced = 0;
			return 0;
		}
		strm->seq = hdr->seq;
		int left = strm->pkts_per_frame - strm->pkt_num;
		if (left <= lost) {
			strm->pkt_num = lost - left;
			strm->valid_pkts = strm->got_pkts;
			strm->got_pkts = 0;
			got_frame = 1;
			strm->timestamp = strm->last_timestamp;
			strm->valid_frames++;
		} else {
			strm->pkt_num += lost;
		}
	}

	// check the header to make sure it's what we expect
	if (!(strm->pkt_num == 0 && hdr->flag == sof) &&
	    !(strm->pkt_num == strm->pkts_per_frame-1 && hdr->flag == eof) &&
	    !(strm->pkt_num > 0 && strm->pkt_num < strm->pkts_per_frame-1 && hdr->flag == mof)) {
		FN_LOG(strm->valid_frames < 2 ? LL_SPEW : LL_NOTICE, \
		       "[Stream %02x] Inconsistent flag %02x with %d packets in buf (%d total), resyncing...\n",
		       strm->flag, hdr->flag, strm->pkt_num, strm->pkts_per_frame);
		strm->synced = 0;
		return got_frame;
	}

	// copy data
	if (datalen > strm->pkt_size) {
		FN_LOG(strm->valid_frames < 2 ? LL_SPEW : LL_WARNING, \
		       "[Stream %02x] Expected %d data bytes, but got %d. Dropping...\n", strm->flag, strm->pkt_size, datalen);
		return got_frame;
	}

	if (datalen != strm->pkt_size && hdr->flag != eof)
		FN_LOG(strm->valid_frames < 2 ? LL_SPEW : LL_WARNING, \
		       "[Stream %02x] Expected %d data bytes, but got only %d\n", strm->flag, strm->pkt_size, datalen);

	uint8_t *dbuf = strm->raw_buf + strm->pkt_num * strm->pkt_size;
	memcpy(dbuf, data, datalen);

	strm->pkt_num++;
	strm->seq++;
	strm->got_pkts++;

	strm->last_timestamp = hdr->timestamp;

	if (strm->pkt_num == strm->pkts_per_frame) {
		strm->pkt_num = 0;
		strm->valid_pkts = strm->got_pkts;
		strm->got_pkts = 0;
		strm->timestamp = hdr->timestamp;
		strm->valid_frames++;
		return 1;
	} else {
		return got_frame;
	}
}

static void stream_initbufs(freenect_context *ctx, packet_stream *strm, int rlen, int plen)
{
	if (strm->usr_buf) {
		strm->lib_buf = NULL;
		strm->proc_buf = strm->usr_buf;
	} else {
		strm->lib_buf = malloc(plen);
		strm->proc_buf = strm->lib_buf;
	}

	if (rlen == 0) {
		strm->split_bufs = 0;
		strm->raw_buf = strm->proc_buf;
	} else {
		strm->split_bufs = 1;
		strm->raw_buf = malloc(rlen);
	}
}

static void stream_freebufs(freenect_context *ctx, packet_stream *strm)
{
	if (strm->split_bufs)
		free(strm->raw_buf);
	if (strm->lib_buf)
		free(strm->lib_buf);

	strm->raw_buf = NULL;
	strm->proc_buf = NULL;
	strm->lib_buf = NULL;
}

static int stream_setbuf(freenect_context *ctx, packet_stream *strm, void *pbuf)
{
	if (!strm->running) {
		strm->usr_buf = pbuf;
		return 0;
	} else {
		if (!pbuf && !strm->lib_buf) {
			FN_ERROR("Attempted to set buffer to NULL but stream was started with no internal buffer\n");
			return -1;
		}
		strm->usr_buf = pbuf;

		if (!pbuf)
			strm->proc_buf = strm->lib_buf;
		else
			strm->proc_buf = pbuf;

		if (!strm->split_bufs)
			strm->raw_buf = strm->proc_buf;
		return 0;
	}
}

// Unpack buffer of (vw bit) data into padded 16bit buffer.
static inline void convert_packed_to_16bit(uint8_t *raw, uint16_t *frame, int vw, int len)
{
	int mask = (1 << vw) - 1;
	uint32_t buffer = 0;
	int bitsIn = 0;
	while (len--) {
		while (bitsIn < vw) {
			buffer = (buffer << 8) | *(raw++);
			bitsIn += 8;
		}
		bitsIn -= vw;
		*(frame++) = (buffer >> bitsIn) & mask;
	}
}

// Unpack buffer of (vw bit) data into 8bit buffer, dropping LSBs
static inline void convert_packed_to_8bit(uint8_t *raw, uint8_t *frame, int vw, int len)
{
	uint32_t buffer = 0;
	int bitsIn = 0;
	while (len--) {
		while (bitsIn < vw) {
			buffer = (buffer << 8) | *(raw++);
			bitsIn += 8;
		}
		bitsIn -= vw;
		*(frame++) = buffer >> (bitsIn+vw-8);
	}
}

static void depth_process(freenect_device *dev, uint8_t *pkt, int len)
{
	freenect_context *ctx = dev->parent;

	if (len == 0)
		return;

	if (!dev->depth.running)
		return;

	int got_frame = stream_process(ctx, &dev->depth, pkt, len);

	if (!got_frame)
		return;

	FN_SPEW("Got depth frame %d/%d packets arrived, TS %08x\n",
	       dev->depth.valid_pkts, dev->depth.pkts_per_frame, dev->depth.timestamp);

	switch (dev->depth_format) {
		case FREENECT_DEPTH_11BIT:
			convert_packed_to_16bit(dev->depth.raw_buf, dev->depth.proc_buf, 11, FREENECT_FRAME_PIX);
			break;
		case FREENECT_DEPTH_10BIT:
			convert_packed_to_16bit(dev->depth.raw_buf, dev->depth.proc_buf, 10, FREENECT_FRAME_PIX);
			break;
		case FREENECT_DEPTH_10BIT_PACKED:
		case FREENECT_DEPTH_11BIT_PACKED:
			break;
	}
	if (dev->depth_cb)
		dev->depth_cb(dev, dev->depth.proc_buf, dev->depth.timestamp);
}

static void video_process(freenect_device *dev, uint8_t *pkt, int len)
{
	freenect_context *ctx = dev->parent;
	int x,y,i;

	if (len == 0)
		return;

	if (!dev->video.running)
		return;

	int got_frame = stream_process(ctx, &dev->video, pkt, len);

	if (!got_frame)
		return;

	FN_SPEW("Got RGB frame %d/%d packets arrived, TS %08x\n", dev->video.valid_pkts,
	       dev->video.pkts_per_frame, dev->video.timestamp);

	uint8_t *raw_buf = dev->video.raw_buf;
	uint8_t *proc_buf = dev->video.proc_buf;
	switch (dev->video_format) {
		case FREENECT_VIDEO_RGB:
		/* Pixel arrangement:
		 * G R G R G R G R
		 * B G B G B G B G
		 * G R G R G R G R
		 * B G B G B G B G
		 * G R G R G R G R
		 * B G B G B G B G
		 */
		for (y=0; y<480; y++) {
			for (x=0; x<640; x++) {
				i = (y*640+x);
				if ((y&1) == 0) {
					if ((x&1) == 0) {
						// topleft G pixel
						uint8_t rr = raw_buf[i+1];
						uint8_t rl = x == 0 ? rr : raw_buf[i-1];
						uint8_t bb = raw_buf[i+640];
						uint8_t bt = y == 0 ? bb : raw_buf[i-640];
						proc_buf[3*i+0] = (rl+rr)>>1;
						proc_buf[3*i+1] = raw_buf[i];
						proc_buf[3*i+2] = (bt+bb)>>1;
					} else {
						// R pixel
						uint8_t gl = raw_buf[i-1];
						uint8_t gr = x == 639 ? gl : raw_buf[i+1];
						uint8_t gb = raw_buf[i+640];
						uint8_t gt = y == 0 ? gb : raw_buf[i-640];
						uint8_t bbl = raw_buf[i+639];
						uint8_t btl = y == 0 ? bbl : raw_buf[i-641];
						uint8_t bbr = x == 639 ? bbl : raw_buf[i+641];
						uint8_t btr = x == 639 ? btl : y == 0 ? bbr : raw_buf[i-639];
						proc_buf[3*i+0] = raw_buf[i];
						proc_buf[3*i+1] = (gl+gr+gb+gt)>>2;
						proc_buf[3*i+2] = (bbl+btl+bbr+btr)>>2;
					}
				} else {
					if ((x&1) == 0) {
						// B pixel
						uint8_t gr = raw_buf[i+1];
						uint8_t gl = x == 0 ? gr : raw_buf[i-1];
						uint8_t gt = raw_buf[i-640];
						uint8_t gb = y == 479 ? gt : raw_buf[i+640];
						uint8_t rtr = raw_buf[i-639];
						uint8_t rbr = y == 479 ? rtr : raw_buf[i+641];
						uint8_t rtl = x == 0 ? rtr : raw_buf[i-641];
						uint8_t rbl = x == 0 ? rbr : y == 479 ? rtl : raw_buf[i+639];
						proc_buf[3*i+0] = (rbl+rtl+rbr+rtr)>>2;
						proc_buf[3*i+1] = (gl+gr+gb+gt)>>2;
						proc_buf[3*i+2] = raw_buf[i];
					} else {
						// botright G pixel
						uint8_t bl = raw_buf[i-1];
						uint8_t br = x == 639 ? bl : raw_buf[i+1];
						uint8_t rt = raw_buf[i-640];
						uint8_t rb = y == 479 ? rt : raw_buf[i+640];
						proc_buf[3*i+0] = (rt+rb)>>1;
						proc_buf[3*i+1] = raw_buf[i];
						proc_buf[3*i+2] = (bl+br)>>1;
					}
				}
			}
		}
		break;
		case FREENECT_VIDEO_BAYER:
			break;
		case FREENECT_VIDEO_IR_10BIT:
			convert_packed_to_16bit(dev->video.raw_buf, dev->video.proc_buf, 10, FREENECT_IR_FRAME_PIX);
			break;
		case FREENECT_VIDEO_IR_10BIT_PACKED:
			break;
		case FREENECT_VIDEO_IR_8BIT:
			convert_packed_to_8bit(dev->video.raw_buf, dev->video.proc_buf, 10, FREENECT_IR_FRAME_PIX);
			break;
	}

	if (dev->video_cb)
		dev->video_cb(dev, dev->video.proc_buf, dev->video.timestamp);
}

typedef struct {
	uint8_t magic[2];
	uint16_t len;
	uint16_t cmd;
	uint16_t tag;
} cam_hdr;

static int send_cmd(freenect_device *dev, uint16_t cmd, void *cmdbuf, unsigned int cmd_len, void *replybuf, unsigned int reply_len)
{
	freenect_context *ctx = dev->parent;
	int res, actual_len;
	uint8_t obuf[0x400];
	uint8_t ibuf[0x200];
	cam_hdr *chdr = (void*)obuf;
	cam_hdr *rhdr = (void*)ibuf;

	if (cmd_len & 1 || cmd_len > (0x400 - sizeof(*chdr))) {
		FN_ERROR("send_cmd: Invalid command length (0x%x)\n", cmd_len);
		return -1;
	}

	chdr->magic[0] = 0x47;
	chdr->magic[1] = 0x4d;
	chdr->cmd = cmd;
	chdr->tag = dev->cam_tag;
	chdr->len = cmd_len / 2;

	memcpy(obuf+sizeof(*chdr), cmdbuf, cmd_len);

	res = fnusb_control(&dev->usb_cam, 0x40, 0, 0, 0, obuf, cmd_len + sizeof(*chdr));
	FN_SPEW("Control cmd=%04x tag=%04x len=%04x: %d\n", cmd, dev->cam_tag, cmd_len, res);
	if (res < 0) {
		FN_ERROR("send_cmd: Output control transfer failed (%d)\n", res);
		return res;
	}

	do {
		actual_len = fnusb_control(&dev->usb_cam, 0xc0, 0, 0, 0, ibuf, 0x200);
	} while (actual_len == 0);
	FN_SPEW("Control reply: %d\n", res);
	if (actual_len < sizeof(*rhdr)) {
		FN_ERROR("send_cmd: Input control transfer failed (%d)\n", res);
		return res;
	}
	actual_len -= sizeof(*rhdr);

	if (rhdr->magic[0] != 0x52 || rhdr->magic[1] != 0x42) {
		FN_ERROR("send_cmd: Bad magic %02x %02x\n", rhdr->magic[0], rhdr->magic[1]);
		return -1;
	}
	if (rhdr->cmd != chdr->cmd) {
		FN_ERROR("send_cmd: Bad cmd %02x != %02x\n", rhdr->cmd, chdr->cmd);
		return -1;
	}
	if (rhdr->tag != chdr->tag) {
		FN_ERROR("send_cmd: Bad tag %04x != %04x\n", rhdr->tag, chdr->tag);
		return -1;
	}
	if (rhdr->len != (actual_len/2)) {
		FN_ERROR("send_cmd: Bad len %04x != %04x\n", rhdr->len, (int)(actual_len/2));
		return -1;
	}

	if (actual_len > reply_len) {
		FN_WARNING("send_cmd: Data buffer is %d bytes long, but got %d bytes\n", reply_len, actual_len);
		memcpy(replybuf, ibuf+sizeof(*rhdr), reply_len);
	} else {
		memcpy(replybuf, ibuf+sizeof(*rhdr), actual_len);
	}

	dev->cam_tag++;

	return actual_len;
}

static int write_register(freenect_device *dev, uint16_t reg, uint16_t data)
{
	freenect_context *ctx = dev->parent;
	uint16_t reply[2];
	uint16_t cmd[2];
	int res;

	cmd[0] = reg;
	cmd[1] = data;

	FN_DEBUG("Write Reg 0x%04x <= 0x%02x\n", reg, data);
	res = send_cmd(dev, 0x03, cmd, 4, reply, 4);
	if (res < 0)
		return res;
	if (res != 2) {
		FN_WARNING("send_cmd returned %d [%04x %04x], 0000 expected\n", res, reply[0], reply[1]);
	}
	return 0;
}

int freenect_start_depth(freenect_device *dev)
{
	freenect_context *ctx = dev->parent;
	int res;

	if (dev->depth.running)
		return -1;

	switch (dev->depth_format) {
		case FREENECT_DEPTH_11BIT:
			stream_initbufs(ctx, &dev->depth, FREENECT_DEPTH_11BIT_PACKED_SIZE, FREENECT_DEPTH_11BIT_SIZE);
			dev->depth.pkts_per_frame = DEPTH_PKTS_11_BIT_PER_FRAME;
			break;
		case FREENECT_DEPTH_10BIT:
			stream_initbufs(ctx, &dev->depth, FREENECT_DEPTH_10BIT_PACKED_SIZE, FREENECT_DEPTH_10BIT_SIZE);
			dev->depth.pkts_per_frame = DEPTH_PKTS_10_BIT_PER_FRAME;
			break;
		case FREENECT_DEPTH_11BIT_PACKED:
			stream_initbufs(ctx, &dev->depth, 0, FREENECT_DEPTH_11BIT_PACKED_SIZE);
			dev->depth.pkts_per_frame = DEPTH_PKTS_11_BIT_PER_FRAME;
			break;
		case FREENECT_DEPTH_10BIT_PACKED:
			stream_initbufs(ctx, &dev->depth, 0, FREENECT_DEPTH_11BIT_PACKED_SIZE);
			dev->depth.pkts_per_frame = DEPTH_PKTS_10_BIT_PER_FRAME;
			break;
	}

	dev->depth.pkt_size = DEPTH_PKTDSIZE;
	dev->depth.synced = 0;
	dev->depth.flag = 0x70;
	dev->depth.valid_frames = 0;

	res = fnusb_start_iso(&dev->usb_cam, &dev->depth_isoc, depth_process, 0x82, NUM_XFERS, PKTS_PER_XFER, DEPTH_PKTBUF);
	if (res < 0)
		return res;

	write_register(dev, 0x06, 0x00); // reset depth stream
	switch (dev->depth_format) {
		case FREENECT_DEPTH_11BIT:
		case FREENECT_DEPTH_11BIT_PACKED:
			write_register(dev, 0x12, 0x03);
			break;
		case FREENECT_DEPTH_10BIT:
		case FREENECT_DEPTH_10BIT_PACKED:
			write_register(dev, 0x12, 0x02);
			break;
	}
	write_register(dev, 0x13, 0x01);
	write_register(dev, 0x14, 0x1e);
	write_register(dev, 0x06, 0x02); // start depth stream

	dev->depth.running = 1;
	return 0;
}

int freenect_start_video(freenect_device *dev)
{
	freenect_context *ctx = dev->parent;
	int res;

	if (dev->video.running)
		return -1;

	switch (dev->video_format) {
		case FREENECT_VIDEO_RGB:
			stream_initbufs(ctx, &dev->video, FREENECT_VIDEO_BAYER_SIZE, FREENECT_VIDEO_RGB_SIZE);
			dev->video.pkts_per_frame = VIDEO_PKTS_PER_FRAME;
			break;
		case FREENECT_VIDEO_BAYER:
			stream_initbufs(ctx, &dev->video, 0, FREENECT_VIDEO_BAYER_SIZE);
			dev->video.pkts_per_frame = VIDEO_PKTS_PER_FRAME;
			break;
		case FREENECT_VIDEO_IR_8BIT:
			stream_initbufs(ctx, &dev->video, FREENECT_VIDEO_IR_10BIT_PACKED_SIZE, FREENECT_VIDEO_IR_8BIT_SIZE);
			dev->video.pkts_per_frame = VIDEO_PKTS_PER_FRAME_IR;
			break;
		case FREENECT_VIDEO_IR_10BIT:
			stream_initbufs(ctx, &dev->video, FREENECT_VIDEO_IR_10BIT_PACKED_SIZE, FREENECT_VIDEO_BAYER_SIZE);
			dev->video.pkts_per_frame = VIDEO_PKTS_PER_FRAME_IR;
			break;
		case FREENECT_VIDEO_IR_10BIT_PACKED:
			stream_initbufs(ctx, &dev->video, 0, FREENECT_VIDEO_IR_10BIT_PACKED_SIZE);
			dev->video.pkts_per_frame = VIDEO_PKTS_PER_FRAME_IR;
			break;
	}

	dev->video.pkt_size = VIDEO_PKTDSIZE;
	dev->video.synced = 0;
	dev->video.flag = 0x80;
	dev->video.valid_frames = 0;

	res = fnusb_start_iso(&dev->usb_cam, &dev->video_isoc, video_process, 0x81, NUM_XFERS, PKTS_PER_XFER, VIDEO_PKTBUF);
	if (res < 0)
		return res;

	write_register(dev, 0x05, 0x00); // reset video stream
	write_register(dev, 0x0c, 0x00);
	write_register(dev, 0x0d, 0x01);
	write_register(dev, 0x0e, 0x1e); // 30Hz bayer
	switch (dev->video_format) {
		case FREENECT_VIDEO_RGB:
		case FREENECT_VIDEO_BAYER:
			write_register(dev, 0x05, 0x01); // start video stream
			break;
		case FREENECT_VIDEO_IR_8BIT:
		case FREENECT_VIDEO_IR_10BIT:
		case FREENECT_VIDEO_IR_10BIT_PACKED:
			write_register(dev, 0x05, 0x03); // start video stream
			break;
	}
	write_register(dev, 0x47, 0x00); // disable Hflip

	dev->video.running = 1;
	return 0;
}

int freenect_stop_depth(freenect_device *dev)
{
	freenect_context *ctx = dev->parent;
	int res;

	if (!dev->depth.running)
		return -1;

	dev->depth.running = 0;
	write_register(dev, 0x06, 0x00); // stop depth stream

	res = fnusb_stop_iso(&dev->usb_cam, &dev->depth_isoc);
	if (res < 0) {
		FN_ERROR("Failed to stop depth isochronous stream: %d\n", res);
		return res;
	}

	stream_freebufs(ctx, &dev->depth);
	return 0;
}

int freenect_stop_video(freenect_device *dev)
{
	freenect_context *ctx = dev->parent;
	int res;

	if (!dev->video.running)
		return -1;

	dev->video.running = 0;
	write_register(dev, 0x05, 0x00); // stop video stream

	res = fnusb_stop_iso(&dev->usb_cam, &dev->video_isoc);
	if (res < 0) {
		FN_ERROR("Failed to stop RGB isochronous stream: %d\n", res);
		return res;
	}

	stream_freebufs(ctx, &dev->video);
	return 0;
}

void freenect_set_depth_callback(freenect_device *dev, freenect_depth_cb cb)
{
	dev->depth_cb = cb;
}

void freenect_set_video_callback(freenect_device *dev, freenect_video_cb cb)
{
	dev->video_cb = cb;
}

int freenect_set_video_format(freenect_device *dev, freenect_video_format fmt)
{
	freenect_context *ctx = dev->parent;
	if (dev->video.running) {
		FN_ERROR("Tried to set video format while stream is active\n");
		return -1;
	}

	switch (fmt) {
		case FREENECT_VIDEO_RGB:
		case FREENECT_VIDEO_BAYER:
		case FREENECT_VIDEO_IR_8BIT:
		case FREENECT_VIDEO_IR_10BIT:
		case FREENECT_VIDEO_IR_10BIT_PACKED:
			dev->video_format = fmt;
			return 0;
		default:
			FN_ERROR("Invalid video format %d\n", fmt);
			return -1;
	}
}

int freenect_set_depth_format(freenect_device *dev, freenect_depth_format fmt)
{
	freenect_context *ctx = dev->parent;
	if (dev->depth.running) {
		FN_ERROR("Tried to set depth format while stream is active\n");
		return -1;
	}
	switch (fmt) {
		case FREENECT_DEPTH_11BIT:
		case FREENECT_DEPTH_10BIT:
		case FREENECT_DEPTH_11BIT_PACKED:
		case FREENECT_DEPTH_10BIT_PACKED:
			dev->depth_format = fmt;
			return 0;
		default:
			FN_ERROR("Invalid depth format %d\n", fmt);
			return -1;
	}
	return 0;
}

int freenect_set_depth_buffer(freenect_device *dev, void *buf)
{
	return stream_setbuf(dev->parent, &dev->depth, buf);
}

int freenect_set_video_buffer(freenect_device *dev, void *buf)
{
	return stream_setbuf(dev->parent, &dev->video, buf);
}
