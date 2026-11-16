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
 * sdb for slot b), and a preloader that the boot ROM rejects leaves a phone
 * that only reaches BROM mode. AOSP ROM zips carry no preloader and the AOSP
 * boot HAL never touches the boot LU, so the copy behind the other slot can
 * be missing or left over from an older firmware. The boot LU is therefore
 * switched only when that is known to be safe:
 *   - both LUs hold the same bytes (the switch changes nothing), or
 *   - the target LU was rewritten while this HAL was running, which is what
 *     a HyperOS package does right before it asks for the slot switch.
 * In every other case the phone keeps booting the preloader it is using
 * now, as it does under the AOSP boot HAL. */
static const char *boot_lu_path(int boot)
{
    return boot == 2 ? "/dev/block/sdb" : "/dev/block/sda";
}

/* Boot LUs are 1 MiB on malachite, so reading one whole is cheap. */
static bool read_boot_lu(int boot, std::string *data)
{
    data->clear();
    if (!android::base::ReadFileToString(boot_lu_path(boot), data) || data->empty()) {
        LOG(ERROR) << "cannot read " << boot_lu_path(boot) << ": " << strerror(errno);
        data->clear();
        return false;
    }
    return true;
}

/* A real preloader image: a UFS/COMBO/EMMC boot header followed by the "MMM"
 * preloader header, the same layout mtk_plpath_utils expects. */
static bool preloader_valid(const std::string &lu)
{
    size_t pl_off;

    if (!lu.compare(0, 4, "EMMC"))
        pl_off = 0x800;
    else if (!lu.compare(0, 3, "UFS") || !lu.compare(0, 4, "COMB"))
        pl_off = 0x1000;
    else
        return false;
    return lu.size() >= pl_off + 3 && !lu.compare(pl_off, 3, "MMM");
}

static bool ufs_set_active_boot_part(int boot)
{
    struct ufs_ioctl_query_data idata;
    unsigned char buf[1];
    int fd, ret = true;

    fd = open("/dev/block/sdc", O_RDWR);
    if (fd < 0) {
        LOG(ERROR) << "cannot open /dev/block/sdc: " << strerror(errno);
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

void BootControlExt::Init() {
  /* Remember what both boot LUs hold before anything is flashed. */
  read_boot_lu(1, &initial_lu_[0]);
  read_boot_lu(2, &initial_lu_[1]);
}

bool BootControlExt::SetBootRegionSlot(unsigned int slot) {
  int boot_part = 0;
  std::string target, other;

  LOG(INFO) << "setActiveBootSlot SetBootRegionSlot " << slot;
  /* slot 0 is A , slot 1 is B */
  if (slot >= 2) {
    LOG(ERROR) << "Wrong Slot value " << slot;
    return false;
  }

  if(slot)
    boot_part = 2;
  else
    boot_part = 1;

  /* The slot itself is already switched in misc at this point. Keeping the
   * current boot LU is not a failure, so every "keep" path returns true;
   * returning false would report a finished install as failed. */
  if (!read_boot_lu(boot_part, &target) || !preloader_valid(target)) {
    LOG(WARNING) << boot_lu_path(boot_part)
                 << " does not hold a valid preloader, keeping the current boot LU";
    return true;
  }

  bool same = read_boot_lu(boot_part == 1 ? 2 : 1, &other) && target == other;
  const std::string &before = initial_lu_[boot_part - 1];
  bool rewritten = !before.empty() && target != before;
  if (!same && !rewritten) {
    LOG(WARNING) << boot_lu_path(boot_part) << " holds a different preloader that was not "
                 << "written in this session, keeping the current boot LU";
    return true;
  }

  if (!ufs_set_active_boot_part(boot_part))
      return false;

  return true;
}
#else
void BootControlExt::Init() {
}

bool BootControlExt::SetBootRegionSlot(unsigned int slot) {
  return true;
}
#endif //#if !defined(ARCH_X86)
}
}
