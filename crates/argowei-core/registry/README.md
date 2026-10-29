# OUI registry data

`oui.tsv` maps 24-bit MAC prefixes (IEEE MA-L assignments, "OUIs") to the
registered organization. `argowei_core::oui` embeds it at build time, so
lookups need no database or network access.

## Source and license

The data comes from the public registry of the IEEE Registration Authority
(<https://standards-oui.ieee.org/oui/oui.txt>). The IEEE publishes the
registry for public lookup but does not attach an open-source license to it;
redistributing the prefix-to-organization mapping is common practice (Wireshark,
nmap and the `hwdata` package all ship it). Argowei stores only the prefix and
organization name, not the registrants' addresses. If you redistribute Argowei
in a setting where this matters, review the IEEE terms for the registry.

The current file was generated from the `hwdata` package's copy of `oui.txt`
(the header of `oui.tsv` records the source file and date).

## Updating

```bash
scripts/update-oui.sh                  # download from IEEE
scripts/update-oui.sh path/to/oui.txt  # or use a file you downloaded
```

IEEE's firewall sometimes rejects non-browser clients. If the download fails,
fetch `oui.txt` in a browser and pass the path. Review the diff and commit
`oui.tsv`; the tests check that the table is loaded and resolves well-known
vendors, but not exact names, since IEEE renames organizations.

## Limitations

- Only MA-L (24-bit) assignments. Devices from vendors that bought smaller
  blocks (MA-M, 28-bit, and MA-S, 36-bit) show no vendor.
- Registrants marked "Private" by IEEE are omitted.
- Locally administered addresses (typically MAC randomization, but also
  virtual interfaces) are reported as such and never resolved to a vendor.
- A vendor is not proof of identity: MAC addresses can be spoofed.
