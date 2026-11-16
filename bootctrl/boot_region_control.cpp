/*****************************************************************************
*  Copyright Statement:
*  --------------------
*  This software is protected by Copyright and the information contained
*  herein is confidential. The software may not be copied and the information
*  contained herein may not be used or disclosed except with the written
*  permission of MediaTek Inc. (C) 2020
*
*  BY OPENING THIS FILE, BUYER HEREBY UNEQUIVOCALLY ACKNOWLEDGES AND AGREES
*  THAT THE SOFTWARE/FIRMWARE AND ITS DOCUMENTATIONS ("MEDIATEK SOFTWARE")
*  RECEIVED FROM MEDIATEK AND/OR ITS REPRESENTATIVES ARE PROVIDED TO BUYER ON
*  AN "AS-IS" BASIS ONLY. MEDIATEK EXPRESSLY DISCLAIMS ANY AND ALL WARRANTIES,
*  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
*  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NONINFRINGEMENT.
*  NEITHER DOES MEDIATEK PROVIDE ANY WARRANTY WHATSOEVER WITH RESPECT TO THE
*  SOFTWARE OF ANY THIRD PARTY WHICH MAY BE USED BY, INCORPORATED IN, OR
*  SUPPLIED WITH THE MEDIATEK SOFTWARE, AND BUYER AGREES TO LOOK ONLY TO SUCH
*  THIRD PARTY FOR ANY WARRANTY CLAIM RELATING THERETO. MEDIATEK SHALL ALSO
*  NOT BE RESPONSIBLE FOR ANY MEDIATEK SOFTWARE RELEASES MADE TO BUYER'S
*  SPECIFICATION OR TO CONFORM TO A PARTICULAR STANDARD OR OPEN FORUM.
*
*  BUYER'S SOLE AND EXCLUSIVE REMEDY AND MEDIATEK'S ENTIRE AND CUMULATIVE
*  LIABILITY WITH RESPECT TO THE MEDIATEK SOFTWARE RELEASED HEREUNDER WILL BE,
*  AT MEDIATEK'S OPTION, TO REVISE OR REPLACE THE MEDIATEK SOFTWARE AT ISSUE,
*  OR REFUND ANY SOFTWARE LICENSE FEES OR SERVICE CHARGE PAID BY BUYER TO
*  MEDIATEK FOR SUCH MEDIATEK SOFTWARE AT ISSUE.
*
*  THE TRANSACTION CONTEMPLATED HEREUNDER SHALL BE CONSTRUED IN ACCORDANCE
*  WITH THE LAWS OF THE STATE OF CALIFORNIA, USA, EXCLUDING ITS CONFLICT OF
*  LAWS PRINCIPLES.  ANY DISPUTES, CONTROVERSIES OR CLAIMS ARISING THEREOF AND
*  RELATED THERETO SHALL BE SETTLED BY ARBITRATION IN SAN FRANCISCO, CA, UNDER
*  THE RULES OF THE INTERNATIONAL CHAMBER OF COMMERCE (ICC).
*
*****************************************************************************/

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <android-base/file.h>
#include <android-base/logging.h>

#if !defined(ARCH_X86)
#include <ufs-mtk-ioctl.h>
#include <sys/ioctl.h>
#endif

#include "boot_region_control_private.h"

namespace android {
namespace bootable {
#if !defined(ARCH_X86)
/* The boot ROM loads the preloader from the active boot LU (sda for slot a,
 * sdb for slot b). ROM zips carry no preloader, so before switching make sure
 * the target LU holds a real preloader: a UFS/COMBO/EMMC boot header followed
 * by the "MMM" preloader header, the same layout mtk_plpath_utils expects.
 * If it does not, refuse the switch instead of leaving a phone that only
 * reaches BROM mode. */
static bool preloader_lu_valid(int boot)
{
    const char *dev = boot == 2 ? "/dev/block/sdb" : "/dev/block/sda";
    char head[4] = {0}, pl[3] = {0};
    int fd = open(dev, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG(ERROR) << "cannot open " << dev << ": " << strerror(errno);
        return false;
    }
    bool ok = android::base::ReadFully(fd, head, sizeof(head));
    off_t pl_off = !strncmp(head, "EMMC", 4) ? 0x800 : 0x1000;
    ok = ok && (!strncmp(head, "UFS", 3) || !strncmp(head, "COMB", 4) || !strncmp(head, "EMMC", 4));
    ok = ok && lseek(fd, pl_off, SEEK_SET) == pl_off &&
         android::base::ReadFully(fd, pl, sizeof(pl)) && !strncmp(pl, "MMM", 3);
    close(fd);
    if (!ok)
        LOG(ERROR) << dev << " does not hold a valid preloader";
    return ok;
}

static bool ufs_set_active_boot_part(int boot)
{
    struct ufs_ioctl_query_data idata;
    unsigned char buf[1];
    int fd, ret = true;

    fd = open("/dev/block/sdc", O_RDWR);
    if (fd < 0) {
        printf("%s: open device failed, err: %d\n", __func__, fd);
        return false;
    }

    buf[0] = boot;           /* 1: BootLU A, 2: BootLU B */

    idata.opcode = UPIU_QUERY_OPCODE_WRITE_ATTR;
    idata.idn = QUERY_ATTR_IDN_BOOT_LUN_EN;
    idata.idx = 0;
    idata.buf_ptr = &buf[0];
    idata.buf_byte = 1;

    if (ioctl(fd, UFS_IOCTL_QUERY, &idata) < 0) {
      LOG(ERROR) << "ufs_set boot_part fail";
      ret = false;
    }
    close(fd);
    return ret;
}

bool BootControlExt::SetBootRegionSlot(unsigned int slot) {
  int boot_part = 0;


  LOG(ERROR) << "setActiveBootSlot SetBootRegionSlot " << slot;
  /* slot 0 is A , slot 1 is B */
  if (slot >= 2) {
    LOG(ERROR) << "Wrong Slot value " << slot;
    return 0;
  }

  if(slot)
    boot_part = 2;
  else
    boot_part = 1;

  if (!preloader_lu_valid(boot_part)) {
      LOG(ERROR) << "refusing to switch the boot LU to an invalid preloader";
      return false;
  }

  if (!ufs_set_active_boot_part(boot_part))
      return false;

  return true;
}
#else
bool BootControlExt::SetBootRegionSlot(unsigned int slot) {
  return true;
}
#endif //#if !defined(ARCH_X86)
}
}
