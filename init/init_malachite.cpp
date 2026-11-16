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
    // ro.boot.hwc comes from the bootloader: CN is the China Redmi, everything else is POCO X7
    string hwc = GetProperty("ro.boot.hwc", "");
    string brand = "POCO", model = "24095PCADG", marketname = "POCO X7";
    if (hwc == "CN") {
        brand = "Redmi";
        model = "24090RA29C";
        marketname = "Redmi Note 14 Pro 5G";
    } else if (hwc == "INDIA" || hwc == "IN") {
        model = "24095PCADI";
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
