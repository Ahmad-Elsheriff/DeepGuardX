import pikepdf
import json
import sys
from hashlib import sha256
from datetime import datetime

SUSPICIOUS_KEYS = [
    "/AA", "/JS", "/JavaScript", "/OpenAction",
    "/Launch", "/URI", "/SubmitForm",
    "/AcroForm", "/RichMedia", "/EmbeddedFile"
]

def scan_pdf(file_path: str, file_id: str | None = None) -> dict:
    """
    بسيط لتحليل ملفات PDF من ناحية الأمن السيبراني:
    - JavaScript / Actions
    - Embedded files / Attachments
    - OpenAction / Launch / URI
    - Metadata + File Hash
    - Structural hints (pages, ObjStm, encryption)
    - Profile (benign / phishing_like / dropper_like / ...)
    - Risk Scoring (Low / Medium / High)
    - Decision flags للـ Backend
    """
    report = {
        "file_id": file_id,                     # جاي من الباك لو بعته
        "file_name": file_path,
        "file_hash": None,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "javascript_found": False,
        "embedded_files": 0,
        "suspicious_objects": 0,
        "triggers": [],           # قائمة بالحاجات اللي اعتبرناها suspicious
        "metadata": {},
        "num_pages": None,
        "encrypted": None,
        "objstm_count": None,
        "risk_level": 1,
        "risk_label": "Low",
        "profile": "unknown",
        "engine_version": "pdf-cyber-scanner-v2",
        # قرارات جاهزة للباك إند
        "security_block": False,       # لو True → الملف يتمنع
        "security_decision": "accept"  # accept / review / reject
    }

    print(f"\n[+] Scanning file: {file_path}\n")

    try:
        # حساب Hash للملف (للتتبع والـ SOC)
        with open(file_path, "rb") as f:
            report["file_hash"] = sha256(f.read()).hexdigest()

        pdf = pikepdf.open(file_path)

        # ========= مؤشرات عامة من الـ Root / Structure =========
        try:
            num_pages = len(pdf.pages)
            report["num_pages"] = num_pages

            # هل الملف متشفر
            report["encrypted"] = bool(pdf.is_encrypted)

            # ملفات كتير مالوير بتبقى صفحة واحدة
            if num_pages == 1:
                report["triggers"].append({"type": "SinglePageDocument", "page": 0})
                report["suspicious_objects"] += 1
        except Exception:
            report["num_pages"] = None
            report["encrypted"] = None

        # Metadata
        report["metadata"] = {k: str(v) for k, v in pdf.docinfo.items()}

        # ========= تحليل الصفحات للـ JavaScript و Actions =========
        for idx, page in enumerate(pdf.pages):
            page_str = str(page)

            # 1) قراءة الــ contents stream لو موجود (نص داخل الصفحة)
            try:
                if page.Contents is not None:
                    contents_bytes = bytes(page.Contents.read_bytes())
                    contents_str = contents_bytes.decode("latin-1", errors="ignore")
                else:
                    contents_str = ""
            except Exception:
                contents_str = ""

            # 2) فحص الـ annotations (روابط /URI ، فورم /SubmitForm ، إلخ)
            annots_str = ""
            try:
                if "/Annots" in page:
                    annots = page["/Annots"]
                    annots_str = str(annots)
            except Exception:
                annots_str = ""

            # 3) دمج كل ده مع بعض
            combined = page_str + contents_str + annots_str

            for key in SUSPICIOUS_KEYS:
                if key in combined:
                    report["suspicious_objects"] += 1
                    trigger = {
                        "type": key,
                        "page": idx,
                    }
                    report["triggers"].append(trigger)

                    if key in ["/JS", "/JavaScript"]:
                        report["javascript_found"] = True

        # ========= Embedded files / Attachments =========

        # 1) attachments عن طريق API
        try:
            attached_count = len(pdf.attachments)
        except Exception:
            attached_count = 0

        # 2) EmbeddedFiles في Root لو موجودة
        root_embedded = 0
        if "/EmbeddedFiles" in pdf.Root:
            embedded = pdf.Root["/EmbeddedFiles"]
            try:
                root_embedded = len(embedded)
            except TypeError:
                root_embedded = 1

        # 3) اختار الأكبر (احتياطي)
        report["embedded_files"] = max(attached_count, root_embedded)

        if report["embedded_files"] > 0:
            report["triggers"].append({
                "type": "EmbeddedFiles",
                "count": report["embedded_files"]
            })

        # ========= فحص Object Streams (/ObjStm) =========
        try:
            objstm_count = 0
            for obj in pdf.objects:
                s = str(obj)
                if "/ObjStm" in s:
                    objstm_count += 1
            report["objstm_count"] = objstm_count

            if objstm_count > 0:
                report["triggers"].append({
                    "type": "ObjStmPresent",
                    "count": objstm_count
                })
                report["suspicious_objects"] += 1
        except Exception:
            report["objstm_count"] = None

        # ========= تصنيف نوع الـ PDF (Profile) حسب الـ triggers =========
        js_triggers = [t for t in report["triggers"] if t["type"] in ["/JS", "/JavaScript"]]
        open_launch = [t for t in report["triggers"] if t["type"] in ["/OpenAction", "/Launch"]]
        uri_triggers = [t for t in report["triggers"] if t["type"] == "/URI"]
        submit_triggers = [t for t in report["triggers"] if t["type"] == "/SubmitForm"]
        acro_triggers = [t for t in report["triggers"] if t["type"] == "/AcroForm"]
        embedded_triggers = [t for t in report["triggers"] if t["type"] == "EmbeddedFiles"]

        profile = "benign_like"

        # 1) Dropper / Malware-like: JS + EmbeddedFiles أو JS + Launch/OpenAction
        if js_triggers and (embedded_triggers or open_launch):
            profile = "dropper_like"

        # 2) Phishing-like: روابط كتير + فورمات / SubmitForm
        elif len(uri_triggers) >= 5 and (submit_triggers or acro_triggers):
            profile = "phishing_like"

        # 3) Suspicious Form / Tracking: فورمات بدون JS
        elif submit_triggers or acro_triggers:
            profile = "form_heavy"

        # 4) Document مع مرفقات بس
        elif embedded_triggers:
            profile = "attachment_heavy"

        # 5) لو مفيش تقريبًا أي triggers
        elif report["suspicious_objects"] == 0 and report["embedded_files"] == 0:
            profile = "benign_like"

        report["profile"] = profile

        # ========= فلاغ للروابط الكتير =========
        uri_only = [t for t in report["triggers"] if t["type"] == "/URI"]
        if len(uri_only) > 5:
            report["triggers"].append({
                "type": "ManyExternalLinks",
                "count": len(uri_only)
            })
            report["suspicious_objects"] += 1

        # ========= Risk Scoring =========
        score = 0

        if report["javascript_found"]:
            score += 7  # زوّدنا وزن الـ JS

        if report["embedded_files"] > 0:
            score += 4

        # كل object مشبوه يزود شوية (بحد أقصى 6)
        score += min(report["suspicious_objects"], 6)

        # وجود OpenAction / Launch يرفع السكور
        has_open_or_launch = any(
            t["type"] in ["/OpenAction", "/Launch"] for t in report["triggers"]
        )
        if has_open_or_launch:
            score += 5

        # لو فيه ManyExternalLinks نزود شوية
        has_many_links = any(t["type"] == "ManyExternalLinks" for t in report["triggers"])
        if has_many_links:
            score += 2

        # Single-page + ObjStm يزودوا السكور شوية
        if any(t["type"] == "SinglePageDocument" for t in report["triggers"]):
            score += 1

        if any(t["type"] == "ObjStmPresent" for t in report["triggers"]):
            score += 2

        # تحديد مستوى الخطورة (رقم + label)
        if score >= 10:
            report["risk_level"] = 3
            report["risk_label"] = "High"
        elif score >= 4:
            report["risk_level"] = 2
            report["risk_label"] = "Medium"
        else:
            report["risk_level"] = 1
            report["risk_label"] = "Low"

        # ========= قرار جاهز للباك إند =========
        if report["risk_level"] == 3:
            report["security_block"] = True
            report["security_decision"] = "reject"   # ارفض الملف
        elif report["risk_level"] == 2:
            report["security_block"] = False
            report["security_decision"] = "review"   # يقبل مع تحذير / مراجعة
        else:
            report["security_block"] = False
            report["security_decision"] = "accept"   # يقبل عادي

        # ========= Trigger stats =========
        trigger_stats = {}
        for t in report["triggers"]:
            t_type = t["type"]
            trigger_stats[t_type] = trigger_stats.get(t_type, 0) + 1

        report["trigger_stats"] = trigger_stats
        report["total_triggers"] = len(report["triggers"])

        # ========= High-level flags =========
        report["flags"] = {
            "has_javascript": report["javascript_found"],
            "has_embedded_files": report["embedded_files"] > 0,
            "has_forms": any(t["type"] in ["/AcroForm", "/SubmitForm"] for t in report["triggers"]),
            "has_external_links": any(t["type"] == "/URI" for t in report["triggers"]),
            "is_single_page": report["num_pages"] == 1,
            "has_objstm": (report["objstm_count"] or 0) > 0
        }

        # ========= Explanation نصي بسيط =========
        explanation_parts = []

        if report["javascript_found"]:
            explanation_parts.append("JavaScript code detected inside the PDF.")

        if report["embedded_files"] > 0:
            explanation_parts.append(f"{report['embedded_files']} embedded file(s) detected.")

        if has_open_or_launch:
            explanation_parts.append("Auto-open actions (/OpenAction or /Launch) present.")

        if has_many_links:
            explanation_parts.append("High number of external links (possible phishing behavior).")

        if report["encrypted"]:
            explanation_parts.append("Document is encrypted.")

        if any(t["type"] == "ObjStmPresent" for t in report["triggers"]):
            explanation_parts.append("Object streams (/ObjStm) found, which may indicate obfuscation.")

        if not explanation_parts:
            explanation = "No strong malicious indicators detected. Document looks benign-like."
        else:
            explanation = " ".join(explanation_parts)

        report["explanation"] = explanation

        # حفظ التقرير كـ JSON
        report_file = file_path + ".report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=4)

        # طباعة تقرير مختصر
        print("=== PDF Cyber Scan Report ===")
        print(f"File ID           : {report['file_id']}")
        print(f"File Name         : {report['file_name']}")
        print(f"File SHA256       : {report['file_hash']}")
        print(f"Num Pages         : {report['num_pages']}")
        print(f"Encrypted         : {report['encrypted']}")
        print(f"ObjStm Count      : {report['objstm_count']}")
        print(f"Javascript Found  : {report['javascript_found']}")
        print(f"Embedded Files    : {report['embedded_files']}")
        print(f"Suspicious Obj    : {report['suspicious_objects']}")
        print(f"Metadata          : {report['metadata']}")
        print(f"Risk Level        : {report['risk_label']} ({report['risk_level']})")
        print(f"Profile           : {report['profile']}")
        print(f"Engine Version    : {report['engine_version']}")
        print(f"Security Decision : {report['security_decision']}")
        print(f"Security Block    : {report['security_block']}")
        print(f"Total Triggers    : {report.get('total_triggers')}")
        print(f"Trigger Stats     : {report.get('trigger_stats')}")
        print(f"Flags             : {report.get('flags')}")
        print(f"Explanation       : {report.get('explanation')}")
        print(f"Triggers          : {report['triggers']}")
        print("==============================\n")

        pdf.close()
        return report

    except Exception as e:
        print(f"[!] Error opening PDF: {e}")
        return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python gate.py <pdf_file_path> [file_id]")
        sys.exit(1)

    file_path = sys.argv[1]
    file_id = sys.argv[2] if len(sys.argv) >= 3 else None

    scan_pdf(file_path, file_id=file_id)