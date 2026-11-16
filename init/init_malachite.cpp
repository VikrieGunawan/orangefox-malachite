#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <android-base/properties.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

using android::base::GetProperty;
using std::string;

void property_override(string prop, string value)
{
    auto pi = (prop_info *)__system_property_find(prop.c_str());

    if (pi != nullptr)
        __system_property_update(pi, value.c_str(), value.size());
    else
        __system_property_add(prop.c_str(), prop.size(), value.c_str(), value.size());
}

void vendor_load_properties()
{
    // The bootloader reports the variant in ro.boot.board_id. Stock ships one
    // /odm/etc/build_<board_id>.prop per variant:
    //   S99016AA1, S99016MA1  Redmi Note 14 Pro (China)      24090RA29C
    //   S99116AA1, S99116IA1  Redmi Note 14 Pro 5G (global)  24090RA29G
    //   S99016EA1             Redmi Note 14 Pro 5G (India)   24090RA29I
    //   S99116EA1             POCO X7 (global)               24095PCADG
    //   S99016IA1             POCO X7 (India)                24095PCADI
    // ro.boot.hwc (CN, Global, India) cannot tell a Redmi from a POCO, so it is
    // only the fallback for a board id that is not in the table.
    string board = GetProperty("ro.boot.board_id", "");
    string hwc = GetProperty("ro.boot.hwc", "");
    string brand = "Redmi", model = "24090RA29G", marketname = "Redmi Note 14 Pro 5G";
    if (board == "S99016AA1" || board == "S99016MA1") {
        model = "24090RA29C";
        marketname = "Redmi Note 14 Pro";
    } else if (board == "S99116AA1" || board == "S99116IA1") {
        // the defaults
    } else if (board == "S99016EA1") {
        model = "24090RA29I";
    } else if (board == "S99116EA1") {
        brand = "POCO";
        model = "24095PCADG";
        marketname = "POCO X7";
    } else if (board == "S99016IA1") {
        brand = "POCO";
        model = "24095PCADI";
        marketname = "POCO X7";
    } else if (hwc == "CN") {
        model = "24090RA29C";
        marketname = "Redmi Note 14 Pro";
    } else if (hwc == "India") {
        model = "24090RA29I";
    }

    string prop_partitions[] = {"", "vendor.", "odm."};
    for (const string &prop : prop_partitions)
    {
        property_override(string("ro.product.") + prop + string("brand"), brand);
        property_override(string("ro.product.") + prop + string("manufacturer"), "Xiaomi");
        property_override(string("ro.product.") + prop + string("name"), "malachite");
        property_override(string("ro.product.") + prop + string("device"), "malachite");
        property_override(string("ro.product.") + prop + string("model"), model);
        property_override(string("ro.product.") + prop + string("marketname"), marketname);
        property_override(string("ro.product.") + prop + string("cert"), model);
    }
    // 2024-01-01, older than any malachite firmware, so sideload never rejects a payload as a downgrade
    property_override("ro.bootimage.build.date.utc", "1704067200");
    property_override("ro.build.date.utc", "1704067200");
}
