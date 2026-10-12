"""
BloodHound Parser - HorusEye v2
Parses SharpHound / bloodhound-python JSON output (legacy schema and
BloodHound CE "kind"-based schema). Accepts either a directory containing
the *_users.json / *_groups.json / *_computers.json / *_domains.json /
*_gpos.json files, or a .zip file straight out of SharpHound.

Author: Omar Tamer 🇪🇬
"""
import io
import json
import os
import zipfile
from typing import Dict, List


class BloodHoundParser:
    """
    Parses BloodHound collection output.

    Usage:
        SharpHound.exe -c All --zipfilename bh.zip
        bloodhound-python -d corp.local -u user -p pass -ns 10.10.10.5 -c All

    Accepts:
        --bloodhound ./bloodhound_output/     (directory of .json files)
        --bloodhound ./bloodhound_output.zip  (raw SharpHound zip)
    """

    # BloodHound CE renamed several properties; check both spellings.
    _PROP_ALIASES = {
        "hasspn":        ["hasspn", "hasSPN"],
        "spns":          ["serviceprincipalnames", "spns"],
        "dontreqpreauth": ["dontreqpreauth", "dontRequirePreAuth"],
        "unconstrained": ["unconstraineddelegation", "unconstrainedDelegation"],
        "admincount":    ["admincount", "adminCount"],
        "enabled":       ["enabled"],
        "name":          ["name"],
        "domain":        ["domain"],
        "operatingsystem": ["operatingsystem", "operatingSystem"],
        "distinguishedname": ["distinguishedname", "distinguishedName"],
        "trustedtoauth": ["trustedtoauth", "trustedToAuth"],
        "pwdneverexpires": ["pwdneverexpires", "passwordNeverExpires"],
    }

    def __init__(self, path: str):
        self.path = path

    # ── Entry point ───────────────────────────────────────────────────────────
    def parse(self) -> Dict:
        result = {
            "users":       [],
            "groups":      [],
            "computers":   [],
            "acls":        [],
            "sessions":    [],
            "gpos":        [],
            "trusts":      [],
            "spns":        [],   # kerberoastable users
            "asrep_users": [],   # AS-REP roastable users
            "local_admins":       [],   # {principal, computer} — AdminTo edges
            "delegation_targets": [],   # {principal, target} — AllowedToDelegate
        }

        raw_objects: List[Dict] = []
        for fname, payload in self._iter_json_files():
            objs, kind_hint = self._extract_objects(payload)
            for obj in objs:
                raw_objects.append((obj, self._kind(fname, payload, obj, kind_hint)))

        if not raw_objects:
            return result

        # ── Pass 1: build SID/ObjectIdentifier -> display-name map ─────────
        sid_to_name = {}
        for obj, kind in raw_objects:
            oid = self._objectid(obj)
            name = self._prop(obj, "name") or oid
            if oid:
                sid_to_name[oid] = name

        # ── Pass 2: build result sets ────────────────────────────────────
        seen_names = set()
        for obj, kind in raw_objects:
            props = obj.get("Properties", obj.get("properties", {})) or {}
            name = self._prop(obj, "name") or self._objectid(obj)

            if kind == "users":
                entry = {
                    "name":            name,
                    "domain":          self._prop(obj, "domain") or props.get("domain", ""),
                    "enabled":         self._bool(self._prop(obj, "enabled"), default=True),
                    "admincount":      self._bool(self._prop(obj, "admincount")),
                    "hasspn":          self._bool(self._prop(obj, "hasspn")),
                    "dontreqpreauth":  self._bool(self._prop(obj, "dontreqpreauth")),
                    "unconstrained_delegation": self._bool(self._prop(obj, "unconstrained")),
                    "pwdneverexpires": self._bool(self._prop(obj, "pwdneverexpires")),
                    "source":          "bloodhound",
                }
                if entry["name"] not in seen_names:
                    seen_names.add(entry["name"])
                    result["users"].append(entry)

                spn_list = self._prop(obj, "spns")
                if entry["hasspn"] or spn_list:
                    result["spns"].append({
                        "user": name,
                        "spns": spn_list if isinstance(spn_list, list) else [],
                    })

                if entry["dontreqpreauth"]:
                    result["asrep_users"].append(name)

            elif kind == "groups":
                result["groups"].append({
                    "name":       name,
                    "domain":     self._prop(obj, "domain") or props.get("domain", ""),
                    "admincount": self._bool(self._prop(obj, "admincount")),
                    "members":    self._member_names(obj, sid_to_name),
                })

            elif kind == "computers":
                result["computers"].append({
                    "name":            name,
                    "operatingsystem": self._prop(obj, "operatingsystem") or "",
                    "enabled":         self._bool(self._prop(obj, "enabled"), default=True),
                    "unconstrained_delegation": self._bool(self._prop(obj, "unconstrained")),
                    "trustedtoauth":   self._bool(self._prop(obj, "trustedtoauth")),
                })

                # ── Sessions attached to this computer ───────────────────
                # SharpHound reports three session sources; merge and dedupe.
                seen_sessions = set()
                for skey in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
                    block = obj.get(skey) or {}
                    for s in (block.get("Results") or []) if isinstance(block, dict) else []:
                        user_sid = s.get("UserSID") or s.get("UserId")
                        uname = sid_to_name.get(user_sid, user_sid)
                        if not uname or uname in seen_sessions:
                            continue
                        seen_sessions.add(uname)
                        result["sessions"].append({
                            "UserName":     uname,
                            "ComputerName": name,
                            "source":       "bloodhound",
                        })

                # ── Local administrators (AdminTo edges) ────────────────
                for principal in self._local_admin_names(obj, sid_to_name):
                    result["local_admins"].append({"principal": principal, "computer": name})

            # ── Constrained delegation targets (users and computers) ─────
            if kind in ("users", "computers"):
                for tgt in obj.get("AllowedToDelegate") or []:
                    tid = tgt.get("ObjectIdentifier") if isinstance(tgt, dict) else tgt
                    if tid:
                        result["delegation_targets"].append({
                            "principal": name,
                            "target":    sid_to_name.get(tid, tid),
                        })

            elif kind == "domains":
                for trust in obj.get("Trusts", []) or []:
                    result["trusts"].append({
                        "target_domain": trust.get("TargetDomainName", ""),
                        "direction":     trust.get("TrustDirection", ""),
                        "type":          trust.get("TrustType", ""),
                        "transitive":    trust.get("IsTransitive", False),
                    })

            elif kind == "gpos":
                result["gpos"].append({
                    "name":   name,
                    "domain": self._prop(obj, "domain") or props.get("domain", ""),
                })

            # ── ACLs / ACEs (present on almost every object type) ─────────
            for ace in obj.get("Aces", []) or []:
                principal_sid = ace.get("PrincipalSID", "")
                result["acls"].append({
                    "principal": sid_to_name.get(principal_sid, principal_sid),
                    "target":    name,
                    "right":     ace.get("RightName", ""),
                    "inherited": ace.get("IsInherited", False),
                })

        return result

    # ── File / archive handling ─────────────────────────────────────────────
    def _iter_json_files(self):
        """Yield (filename, parsed_json_dict) for every relevant file."""
        if os.path.isdir(self.path):
            for fname in sorted(os.listdir(self.path)):
                if not fname.lower().endswith(".json"):
                    continue
                fpath = os.path.join(self.path, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        yield fname, json.load(f)
                except (json.JSONDecodeError, OSError):
                    continue

        elif os.path.isfile(self.path) and self.path.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(self.path) as z:
                    for name in z.namelist():
                        if not name.lower().endswith(".json"):
                            continue
                        try:
                            with z.open(name) as f:
                                yield name, json.loads(f.read().decode("utf-8", "ignore"))
                        except json.JSONDecodeError:
                            continue
            except zipfile.BadZipFile:
                return

        elif os.path.isfile(self.path) and self.path.lower().endswith(".json"):
            # Single combined JSON file (some collectors dump one big file)
            try:
                with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                    yield os.path.basename(self.path), json.load(f)
            except (json.JSONDecodeError, OSError):
                return

    # ── Object extraction ───────────────────────────────────────────────────
    def _extract_objects(self, payload):
        """Return (list_of_objects, meta_type_hint) from a parsed JSON payload."""
        if isinstance(payload, dict) and "data" in payload:
            meta = payload.get("meta", {}) or {}
            return payload.get("data") or [], meta.get("type", "")
        if isinstance(payload, list):
            return payload, ""
        return [], ""

    def _kind(self, fname: str, payload, obj: Dict, kind_hint: str) -> str:
        hint = (kind_hint or "").lower()
        for k in ("users", "groups", "computers", "domains", "gpos", "ous", "containers"):
            if k in hint:
                return k
        fname_l = fname.lower()
        for k in ("users", "groups", "computers", "domains", "gpos", "ous", "containers"):
            if k in fname_l:
                return k
        # Fall back to the object's own "kind"/"ObjectType" field (BloodHound CE)
        ot = (obj.get("kind") or obj.get("ObjectType") or obj.get("kinds", [""])[0]
              if isinstance(obj.get("kinds"), list) else obj.get("kind") or obj.get("ObjectType"))
        if ot:
            ot = str(ot).lower()
            if ot.startswith("user"):
                return "users"
            if ot.startswith("group"):
                return "groups"
            if ot.startswith("computer"):
                return "computers"
            if ot.startswith("domain"):
                return "domains"
            if ot.startswith("gpo"):
                return "gpos"
        return "unknown"

    # ── Property helpers ─────────────────────────────────────────────────────
    def _prop(self, obj: Dict, key: str):
        props = obj.get("Properties", obj.get("properties", {})) or {}
        for alias in self._PROP_ALIASES.get(key, [key]):
            if alias in props:
                return props[alias]
            # case-insensitive fallback
            for pk in props:
                if pk.lower() == alias.lower():
                    return props[pk]
        return None

    def _objectid(self, obj: Dict) -> str:
        return obj.get("ObjectIdentifier") or obj.get("id") or obj.get("objectid", "")

    def _bool(self, value, default: bool = False) -> bool:
        if value is None:
            return default
        return bool(value)

    def _local_admin_names(self, obj: Dict, sid_to_name: Dict) -> List[str]:
        """Members of a computer's local Administrators group.

        Legacy SharpHound: ``LocalAdmins.Results``. SharpHound CE:
        ``LocalGroups`` entry whose SID ends in -544 (the builtin Administrators group).
        """
        results = []
        legacy = obj.get("LocalAdmins")
        if isinstance(legacy, dict):
            results.extend(legacy.get("Results") or [])
        for grp in obj.get("LocalGroups") or []:
            if not isinstance(grp, dict):
                continue
            gid = str(grp.get("ObjectIdentifier", ""))
            gname = str(grp.get("Name", "")).upper()
            if gid.endswith("-544") or gname.startswith("ADMINISTRATORS@"):
                results.extend(grp.get("Results") or [])
        names = []
        for r in results:
            sid = r.get("ObjectIdentifier") if isinstance(r, dict) else r
            if sid:
                names.append(sid_to_name.get(sid, sid))
        return names

    def _member_names(self, obj: Dict, sid_to_name: Dict) -> List[str]:
        members = obj.get("Members", []) or []
        names = []
        for m in members:
            sid = m.get("ObjectIdentifier") if isinstance(m, dict) else m
            names.append(sid_to_name.get(sid, sid))
        return names
