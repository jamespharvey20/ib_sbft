/*
 *  Copyright 2016
 *  by James P. Harvey <jamespharvey20@gmail.com>
 *
 * This code exposes the SRP Boot Format Table to userland via sysfs.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2.0 as published by
 * the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/stat.h>

#define SBFT_SRP_VERSION "0.0.1"
#define SBFT_SRP_DATE "2016-Aug-20"

MODULE_AUTHOR("James P. Harvey <jamespharvey20@gmail.com>");
MODULE_DESCRIPTION("sysfs interface to sBFT information");
MODULE_LICENSE("GPL");
MODULE_VERSION(SBFT_SRP_VERSION);

static const char *sbft_signature = { "sBFT" };
#define SBFT_SIGNATURE_LEN 4
#define SBFT_ALIGNMENT 16
#define SBFT_VALID_REGION_START 0 + SBFT_ALIGNMENT /* Don't deref 0 */
#define SBFT_VALID_REGION_END 0x9FFFF /* 1MB - 1 byte */

static struct kobject *kobj = NULL;
static struct sbft_table *sbft = NULL;
static struct sbft_scsi_subtable *sbft_scsi = NULL;
static struct sbft_srp_subtable *sbft_srp = NULL;
static struct sbft_ib_subtable *sbft_ib = NULL;

/*
 * sBFT structures
 */

struct sbft_table {
	struct acpi_table_header acpi_table;
	u16 scsi_subtable_off;
	u16 srp_subtable_off;
	u16 ib_subtable_off;
	u8 reserved[6];
} __attribute__((__packed__));

struct sbft_scsi_subtable {
	u64 lun;
} __attribute__((__packed__));

struct sbft_srp_subtable {
	u64 initiator_port_identifier[2];
	u64 target_port_identifier[2];
} __attribute__((__packed__));

struct sbft_ib_subtable {
	u64 source_gid[2];
	u64 destination_gid[2];
	u64 service_identifier;
	u16 partition_key;
	u8 reserved[6];
} __attribute__((__packed__));

/*
 * Attribute printing routines
 */

static ssize_t sbft_16_to_string(char *buf, u16 source_le)
{
	u16 source_cpu = le16_to_cpu(source_le);
	return sprintf(buf, "%04x\n", source_cpu);
}

static ssize_t sbft_64_to_string(char *buf, u64 source_le)
{
	u64 source_cpu = le64_to_cpu(source_le);
	return sprintf(buf, "%04x:%04x:%04x:%04x\n",
	    (unsigned int)((source_cpu & 0xFFFF000000000000) >> 48),
	    (unsigned int)((source_cpu & 0x0000FFFF00000000) >> 32),
	    (unsigned int)((source_cpu & 0x00000000FFFF0000) >> 16),
	    (unsigned int)((source_cpu & 0x0000000000000FFFF)));
}

static ssize_t sbft_2x64_to_string(char *buf, u64 source_le[])
{
	u64 source_cpu[2];
	source_cpu[0] = le64_to_cpu(source_le[0]);
	source_cpu[1] = le64_to_cpu(source_le[1]);
	return sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
	    (unsigned int)((source_cpu[1] & 0xFFFF000000000000) >> 48),
            (unsigned int)((source_cpu[1] & 0x0000FFFF00000000) >> 32),
            (unsigned int)((source_cpu[1] & 0x00000000FFFF0000) >> 16),
            (unsigned int)((source_cpu[1] & 0x000000000000FFFF)),
            (unsigned int)((source_cpu[0] & 0xFFFF000000000000) >> 48),
            (unsigned int)((source_cpu[0] & 0x0000FFFF00000000) >> 32),
            (unsigned int)((source_cpu[0] & 0x00000000FFFF0000) >> 16),
            (unsigned int)((source_cpu[0] & 0x000000000000FFFF)));
}

static ssize_t sbft_rd_attr_scsi_lun_show(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf)
{
	if (!sbft_scsi)
		return sprintf(buf, "\n");
	return sbft_64_to_string(buf, sbft_scsi->lun);
}

static ssize_t sbft_rd_attr_srp_initiator_port_identifier_show(
    struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	if (!sbft_srp)
		return sprintf(buf, "\n");
	return sbft_2x64_to_string(buf, sbft_srp->initiator_port_identifier);
}

static ssize_t sbft_rd_attr_srp_target_port_identifier_show(
    struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	if (!sbft_srp)
		return sprintf(buf, "\n");
	return sbft_2x64_to_string(buf, sbft_srp->target_port_identifier);
}

static ssize_t sbft_rd_attr_ib_source_gid_show(
   struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	if (!sbft_ib)
		return sprintf(buf, "\n");
	return sbft_2x64_to_string(buf, sbft_ib->source_gid);
}

static ssize_t sbft_rd_attr_ib_destination_gid_show(
    struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	if (!sbft_ib)
		return sprintf(buf, "\n");
	return sbft_2x64_to_string(buf, sbft_ib->destination_gid);
}

static ssize_t sbft_rd_attr_ib_service_identifier_show(
    struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	if (!sbft_ib)
		return sprintf(buf, "\n");
	return sbft_64_to_string(buf, sbft_ib->service_identifier);
}

static ssize_t sbft_rd_attr_ib_partition_key_show(
    struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	if (!sbft_ib)
		return sprintf(buf, "\n");
	return sbft_16_to_string(buf, sbft_ib->partition_key);
}

static ssize_t sbft_rd_attr_acpi_revision_show(
    struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	if (!sbft)
		return sprintf(buf, "\n");
	return sprintf(buf, "%hhd\n", sbft->acpi_table.revision);
}

static ssize_t sbft_rd_attr_acpi_oem_id_show(
    struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	if (!sbft)
		return sprintf(buf, "\n");
	return sprintf(buf, "%.*s\n", ACPI_OEM_ID_SIZE,
		       sbft->acpi_table.oem_id);
}

static ssize_t sbft_rd_attr_acpi_oem_table_id_show(
    struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	if (!sbft)
		return sprintf(buf, "\n");
	return sprintf(buf, "%.*s\n", ACPI_OEM_TABLE_ID_SIZE,
		       sbft->acpi_table.oem_table_id);
}

/*
 * kobject attribute structure
 */

struct sbft_rd_attr {
	struct attribute attr;
	ssize_t (*show) (struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf);
} __attribute__((__packed__));

/*
 * kobject attribute routines
 */

#define SBFT_RD_ATTR(_name) \
static struct sbft_rd_attr sbft_rd_attr_##_name = { \
	.attr = { \
		.name = __stringify(_name), \
		.mode = S_IRUGO \
	}, \
	.show = sbft_rd_attr_##_name##_show, \
};

/*
 * kobject attributes
 */

SBFT_RD_ATTR(scsi_lun);
SBFT_RD_ATTR(srp_initiator_port_identifier);
SBFT_RD_ATTR(srp_target_port_identifier);
SBFT_RD_ATTR(ib_source_gid);
SBFT_RD_ATTR(ib_destination_gid);
SBFT_RD_ATTR(ib_service_identifier);
SBFT_RD_ATTR(ib_partition_key);
SBFT_RD_ATTR(acpi_revision);
SBFT_RD_ATTR(acpi_oem_id);
SBFT_RD_ATTR(acpi_oem_table_id);

static struct attribute *attrs[] = {
	&sbft_rd_attr_scsi_lun.attr,
	&sbft_rd_attr_srp_initiator_port_identifier.attr,
	&sbft_rd_attr_srp_target_port_identifier.attr,
	&sbft_rd_attr_ib_source_gid.attr,
	&sbft_rd_attr_ib_destination_gid.attr,
	&sbft_rd_attr_ib_service_identifier.attr,
	&sbft_rd_attr_ib_partition_key.attr,
	&sbft_rd_attr_acpi_revision.attr,
	&sbft_rd_attr_acpi_oem_id.attr,
	&sbft_rd_attr_acpi_oem_table_id.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};
	
/*
 * If a valid sBFT exists at virt, set sbft, sbft_scsi, sbft_srp, and if
 * applicable, sbft_ib.  Otherwise leaves these as NULL.
 */

#define SBFT_REJECT(_condition, _reason, ...) \
if (_condition) { \
	pr_info("ib_sbft: Rejecting because " _reason "\n", ##__VA_ARGS__); \
	return 0; \
}

static int __init try_setting_sbft(void *virt)
{
	struct sbft_table *possible_sbft = NULL;
	struct sbft_scsi_subtable *possible_sbft_scsi = NULL;
	struct sbft_srp_subtable *possible_sbft_srp = NULL;
	struct sbft_ib_subtable *possible_sbft_ib = NULL;
	u16 scsi_subtable_off = 0;
	u16 srp_subtable_off = 0;
	u16 ib_subtable_off = 0;
	u8 table_sums_to = 0;
	u8 *ptr = NULL;

	pr_info("ib_sbft: Possible sBFT at phy %p, virt %p\n",
		 (void *)virt_to_phys(virt), (void *)virt);

	/* Can't be at 0x0 */

	SBFT_REJECT(!virt, "can't deref 0x0");
	if (!virt)
		return 0;

	possible_sbft = (struct sbft_table *)virt;

	/* Only revision 1 is defined */

	SBFT_REJECT(possible_sbft->acpi_table.revision != 1,
		    "revision is %hhu", possible_sbft->acpi_table.revision);

	/* All fields marked as reserved must be filled with zeros */

	SBFT_REJECT(memcmp(&possible_sbft->acpi_table.oem_revision,
			    "\0\0\0\0\0\0\0\0\0\0\0\0",
			    sizeof(possible_sbft->acpi_table.oem_revision)
			    + sizeof(possible_sbft->acpi_table.asl_compiler_id)
			    + sizeof(possible_sbft->acpi_table.asl_compiler_revision)),
		    "possible_sbft->acpi_table.reserved_acpi isn't filled with zeros");

	SBFT_REJECT(memcmp(possible_sbft->reserved, "\0\0\0\0\0\0",
			    sizeof(possible_sbft->reserved)),
		    "sfbt->reserved isn't filled with zeros");

	/* Subtable offsets can't be too low - remember order is undefined */

	scsi_subtable_off = le16_to_cpu(possible_sbft->scsi_subtable_off);
	SBFT_REJECT(scsi_subtable_off < sizeof(struct sbft_table),
		    "scsi_subtable_off is %hu, too low", scsi_subtable_off);
	possible_sbft_scsi = (struct sbft_scsi_subtable *)
	    (virt + scsi_subtable_off);

	srp_subtable_off = le16_to_cpu(possible_sbft->srp_subtable_off);
	SBFT_REJECT(srp_subtable_off < sizeof(struct sbft_table),
		    "srp_subtable_off is %hu, too low", srp_subtable_off);
	possible_sbft_srp = (struct sbft_srp_subtable *)
	    (virt + srp_subtable_off);

	ib_subtable_off = le16_to_cpu(possible_sbft->ib_subtable_off);
	if (ib_subtable_off != 0) {
		SBFT_REJECT(ib_subtable_off < sizeof(struct sbft_table),
			    "ib_subtable_off is %hu, too low", ib_subtable_off);
		possible_sbft_ib = (struct sbft_ib_subtable *)
		    (virt + ib_subtable_off);
	}

	/* Entire table must sum to zero */

	ptr = (u8 *)possible_sbft;
	while (ptr < (u8 *)possible_sbft + possible_sbft->acpi_table.length)
		table_sums_to += *(ptr++);
	SBFT_REJECT(table_sums_to, "table_sums_to is %hhu", table_sums_to);

	/* Passes */

	sbft = possible_sbft;
	sbft_scsi = possible_sbft_scsi;
	sbft_srp = possible_sbft_srp;
	sbft_ib = possible_sbft_ib;
	return 1;
}

/*
 * Searches physical memory for sbft_signature between SBFT_VALID_REGION_START
 * and SBFT_VALID_REGION_END, at 16-byte aligned locations. If found, checks
 * validity through try_setting_sbft().
 */
static int __init find_sbft_in_mem(void)
{
	void *virt = NULL;
	for (virt = phys_to_virt(SBFT_VALID_REGION_START); virt <
	    phys_to_virt(SBFT_VALID_REGION_END); virt += SBFT_ALIGNMENT) {
		if (!memcmp(virt, sbft_signature, SBFT_SIGNATURE_LEN)
		    && try_setting_sbft(virt)) {
			pr_info("ib_sbft: sBFT found at phy %p, virt %p\n",
			    	(void *)virt_to_phys(virt), (void *)virt);
			return 0;
		}
	}

	pr_warning("ib_sbft: sBFT not found\n");
	return -ENOENT;
}

/*
 * Initializes kernel module
 */
static int __init sbft_init(void)
{
	int rc = 0;

	rc = find_sbft_in_mem();
	if (rc)
		return rc;

	kobj = kobject_create_and_add("sbft", firmware_kobj);
	if (!kobj) {
		pr_warning("ib_sbft: kobject_create_and_add failed\n");
		return -ENOMEM;
	}
	
	rc = sysfs_create_group(kobj, &attr_group);
	if (rc) {
		pr_warning("ib_sbft: sysfs_create_group failed\n");
		kobject_put(kobj);
		return rc;
	}

	return 0;
}

/*
 * Exits kernel module
 */
static void __exit sbft_exit(void)
{
	if (kobj)
		kobject_put(kobj);
}

module_init(sbft_init);
module_exit(sbft_exit);
