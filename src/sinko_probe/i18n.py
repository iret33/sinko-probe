"""English and Arabic strings shared by the terminal, HTML and Telegram reports."""

from enum import Enum

from .models import Category, ExpectedAction, Outcome, Verdict


class Lang(str, Enum):
    EN = "en"
    AR = "ar"


STRINGS: dict[str, dict[str, str]] = {
    "report_title": {"en": "Sinko-Probe Audit Report", "ar": "تقرير فحص سينكو"},
    "compare_title": {
        "en": "Head-to-Head DNS Resolver & Parental Control Benchmark",
        "ar": "مقارنة مباشرة بين محللات DNS وأنظمة الرقابة الأبوية",
    },
    "scorecard_title": {
        "en": "Application Protection Scorecard",
        "ar": "بطاقة أداء حماية التطبيقات",
    },
    "summary_title": {"en": "Sinko Telemetry Summary", "ar": "ملخص قياسات سينكو"},
    "details_title": {"en": "Probe Details", "ar": "تفاصيل الفحوصات"},
    "col_app": {"en": "App Profile", "ar": "التطبيق"},
    "col_domain": {"en": "Domain", "ar": "النطاق"},
    "col_category": {"en": "Category", "ar": "الفئة"},
    "col_expected": {"en": "Expected", "ar": "المتوقع"},
    "col_verdict": {"en": "Verdict", "ar": "النتيجة"},
    "col_answer": {"en": "CNAME / IP", "ar": "الإجابة"},
    "col_latency": {"en": "Latency", "ar": "زمن الاستجابة"},
    "col_result": {"en": "Audit", "ar": "التقييم"},
    "col_probes": {"en": "Probes", "ar": "الفحوصات"},
    "col_blocked": {"en": "Blocked", "ar": "محظور"},
    "col_safesearch": {"en": "SafeSearch", "ar": "البحث الآمن"},
    "col_allowed": {"en": "Core Allowed", "ar": "الأساسي المسموح"},
    "col_errors": {"en": "Errors", "ar": "الأخطاء"},
    "col_avg_latency": {"en": "Avg Latency", "ar": "متوسط الاستجابة"},
    "col_score": {"en": "Score", "ar": "الدرجة"},
    "col_target": {"en": "Resolver Target", "ar": "المحلل المستهدف"},
    "col_endpoint": {"en": "Endpoint", "ar": "نقطة الاتصال"},
    "col_protocol": {"en": "Protocol", "ar": "البروتوكول"},
    "col_p50_p95": {"en": "p50 / p95 Latency", "ar": "زمن الاستجابة p50 / p95"},
    "kpi_compliance": {"en": "Compliance Score", "ar": "درجة الامتثال"},
    "kpi_block": {"en": "Block Efficacy", "ar": "فعالية الحظر"},
    "kpi_safesearch": {"en": "SafeSearch Enforced", "ar": "فرض البحث الآمن"},
    "kpi_false_positives": {"en": "False Positives", "ar": "الحظر الخاطئ"},
    "kpi_errors": {"en": "Errors", "ar": "الأخطاء"},
    "kpi_inconclusive": {"en": "Inconclusive", "ar": "غير حاسمة"},
    "kpi_latency": {"en": "Latency p50 / p95 / p99", "ar": "زمن الاستجابة p50 / p95 / p99"},
    "kpi_compliance_help": {
        "en": "Probes that met the policy, out of every probe that could be judged.",
        "ar": "نسبة الفحوصات التي طابقت السياسة من بين كل الفحوصات القابلة للحكم.",
    },
    "kpi_block_help": {
        "en": "Must-block domains that were blocked.",
        "ar": "النطاقات الواجب حظرها التي حُظرت فعلاً.",
    },
    "kpi_safesearch_help": {
        "en": "Search engines rewritten to their SafeSearch / Restricted Mode address.",
        "ar": "محركات البحث التي أُعيد توجيهها إلى عنوان البحث الآمن أو الوضع المقيد.",
    },
    "kpi_false_positives_help": {
        "en": "Must-allow sites (school, coding, reference) that were wrongly blocked.",
        "ar": "المواقع الواجب السماح بها (المدرسة والبرمجة والمراجع) التي حُظرت خطأً.",
    },
    "kpi_errors_help": {
        "en": "Queries with no usable answer: timeouts, SERVFAIL, TLS or connection failures.",
        "ar": "استعلامات بلا إجابة صالحة: انتهاء المهلة أو SERVFAIL أو فشل TLS أو الاتصال.",
    },
    "kpi_inconclusive_help": {
        "en": "Answers that cannot prove filtering, e.g. names that no longer exist upstream.",
        "ar": "إجابات لا تثبت الحظر، مثل نطاقات لم تعد موجودة لدى الخوادم الأصلية.",
    },
    "kpi_latency_help": {
        "en": "Answered queries only; timeouts are counted as errors instead.",
        "ar": "للاستعلامات التي أُجيبت فقط؛ حالات انتهاء المهلة تُحسب ضمن الأخطاء.",
    },
    "label_target": {"en": "Target", "ar": "الهدف"},
    "label_policy": {"en": "Policy", "ar": "السياسة"},
    "label_waves": {"en": "Waves", "ar": "الجولات"},
    "label_generated": {"en": "Generated", "ar": "تاريخ الإنشاء"},
    "label_findings": {"en": "Findings", "ar": "ملاحظات"},
    "label_no_policy": {"en": "Built-in profile expectations", "ar": "توقعات الملفات المدمجة"},
    "label_probes_summary": {
        "en": "{passed} passed · {failed} failed · {errors} errors · {inconclusive} inconclusive",
        "ar": "{passed} ناجح · {failed} فاشل · {errors} خطأ · {inconclusive} غير حاسم",
    },
    "filter_all": {"en": "All", "ar": "الكل"},
    "filter_failures": {"en": "Failed", "ar": "الفاشلة"},
    "filter_errors": {"en": "Errors", "ar": "الأخطاء"},
    "filter_inconclusive": {"en": "Inconclusive", "ar": "غير الحاسمة"},
    "filter_passed": {"en": "Passed", "ar": "الناجحة"},
    "search_label": {"en": "Search domains and apps", "ar": "ابحث في النطاقات والتطبيقات"},
    "search_placeholder": {"en": "Search…", "ar": "بحث…"},
    "showing": {"en": "Showing {shown} of {total}", "ar": "عرض {shown} من {total}"},
    "theme_toggle": {"en": "Toggle light/dark theme", "ar": "تبديل الوضع الفاتح/الداكن"},
    "na": {"en": "n/a", "ar": "غير متاح"},
    "saved_html": {"en": "HTML dashboard saved:", "ar": "تم حفظ لوحة HTML:"},
    "saved_json": {"en": "JSON report saved:", "ar": "تم حفظ تقرير JSON:"},
    "saved_csv": {"en": "CSV report saved:", "ar": "تم حفظ تقرير CSV:"},
    "simulating": {
        "en": "Simulating {apps} apps against {target} ({endpoint})",
        "ar": "محاكاة {apps} تطبيقات على {target} ({endpoint})",
    },
    "benchmarking": {
        "en": "Benchmarking {target} ({endpoint})…",
        "ar": "جارٍ قياس أداء {target} ({endpoint})…",
    },
    "below_min_score": {
        "en": "Compliance score {score} is below the required {required}%",
        "ar": "درجة الامتثال {score} أقل من الحد المطلوب {required}%",
    },
    "unreachable": {
        "en": "No usable answers from {target} ({endpoint})",
        "ar": "لم تصل أي إجابة صالحة من {target} ({endpoint})",
    },
    "telegram_sent": {"en": "Telegram report delivered.", "ar": "تم إرسال التقرير عبر تيليجرام."},
    "telegram_failed": {
        "en": "Failed to send Telegram notification:",
        "ar": "تعذّر إرسال إشعار تيليجرام:",
    },
    "telegram_title": {"en": "Sinko-Probe DNS Audit", "ar": "فحص DNS من سينكو"},
    "hint_no_answers": {
        "en": "The resolver gave no usable answer to any query ({error}). Check the address, "
        "port and protocol.",
        "ar": "لم يُرجع المحلل أي إجابة صالحة لأي استعلام ({error}). تحقق من العنوان والمنفذ "
        "والبروتوكول.",
    },
    "hint_all_refused": {
        "en": "Every answer was REFUSED, so the resolver is probably rejecting this client "
        "(an ACL) rather than filtering. Block results are not meaningful.",
        "ar": "كانت جميع الإجابات REFUSED، والأرجح أن المحلل يرفض هذا الجهاز (قائمة صلاحيات) "
        "لا أنه يحظر المحتوى. نتائج الحظر هنا غير معبّرة.",
    },
    "hint_some_errors": {
        "en": "{count} of {total} queries got no usable answer; they count against the "
        "compliance score but not against the block or SafeSearch rates.",
        "ar": "{count} من أصل {total} استعلاماً لم تحصل على إجابة صالحة؛ وهي تُخصم من درجة "
        "الامتثال لكنها لا تُحتسب في نسب الحظر أو البحث الآمن.",
    },
    "hint_inconclusive": {
        "en": "{count} domain(s) do not exist upstream, so they cannot prove filtering: "
        "{domains}. Remove dead domains from your profiles.",
        "ar": "{count} نطاق(ات) غير موجودة أصلاً لدى الخوادم الأصلية، فلا يمكنها إثبات الحظر: "
        "{domains}. احذف النطاقات المنتهية من ملفات التعريف.",
    },
    "hint_sinkhole": {
        "en": "{count} unrelated must-block sites all resolved to {ip}. If that is your block "
        "page, re-run with --sinkhole-ip {ip}.",
        "ar": "{count} مواقع غير مترابطة واجبة الحظر أشارت جميعها إلى {ip}. إذا كان هذا عنوان "
        "صفحة الحظر لديك فأعد التشغيل مع --sinkhole-ip {ip}.",
    },
}

VERDICT_LABELS: dict[Verdict, dict[str, str]] = {
    Verdict.BLOCKED_ZERO_IP: {"en": "BLOCKED (Zero/Loopback IP)", "ar": "محظور (عنوان صفري)"},
    Verdict.BLOCKED_NODATA: {"en": "BLOCKED (NODATA)", "ar": "محظور (بلا سجلات)"},
    Verdict.BLOCKED_NXDOMAIN: {"en": "BLOCKED (NXDOMAIN)", "ar": "محظور (NXDOMAIN)"},
    Verdict.BLOCKED_REFUSED: {"en": "BLOCKED (REFUSED)", "ar": "محظور (REFUSED)"},
    Verdict.BLOCKED_SINKHOLE_IP: {"en": "BLOCKED (Sinkhole VIP)", "ar": "محظور (صفحة حظر)"},
    Verdict.SAFESEARCH_ENFORCED: {"en": "ENFORCED (SafeSearch)", "ar": "مُفعّل (بحث آمن)"},
    Verdict.ALLOWED_RESOLVED: {"en": "ALLOWED (Resolved)", "ar": "مسموح (تم التحليل)"},
    Verdict.UPSTREAM_NXDOMAIN: {
        "en": "INCONCLUSIVE (Name does not exist)",
        "ar": "غير حاسم (النطاق غير موجود)",
    },
    Verdict.ERROR_TIMEOUT: {"en": "ERROR (Timeout)", "ar": "خطأ (انتهت المهلة)"},
    Verdict.ERROR_RCODE: {"en": "ERROR (SERVFAIL/RCODE)", "ar": "خطأ (رمز استجابة)"},
    Verdict.ERROR_TRANSPORT: {"en": "ERROR (Transport)", "ar": "خطأ (اتصال)"},
}

CATEGORY_LABELS: dict[Category, dict[str, str]] = {
    Category.ADS: {"en": "ads", "ar": "إعلانات"},
    Category.TELEMETRY: {"en": "telemetry", "ar": "تتبّع"},
    Category.SOCIAL: {"en": "social", "ar": "تواصل اجتماعي"},
    Category.GAMING: {"en": "gaming", "ar": "ألعاب"},
    Category.STREAMING: {"en": "streaming", "ar": "بث"},
    Category.SAFE_SEARCH: {"en": "safe_search", "ar": "بحث آمن"},
    Category.PARENTAL_RESTRICTED: {"en": "parental_restricted", "ar": "محتوى مقيّد"},
    Category.AI_CHATBOTS: {"en": "ai_chatbots", "ar": "روبوتات دردشة"},
    Category.CORE_SERVICE: {"en": "core_service", "ar": "خدمة أساسية"},
    Category.CUSTOM: {"en": "custom", "ar": "مخصص"},
}

EXPECTED_LABELS: dict[ExpectedAction, dict[str, str]] = {
    ExpectedAction.BLOCK: {"en": "BLOCK", "ar": "حظر"},
    ExpectedAction.ALLOW: {"en": "ALLOW", "ar": "سماح"},
    ExpectedAction.SAFESEARCH: {"en": "SAFESEARCH", "ar": "بحث آمن"},
}

OUTCOME_LABELS: dict[Outcome, dict[str, str]] = {
    Outcome.PASS: {"en": "PASS", "ar": "ناجح"},
    Outcome.FAIL: {"en": "FAIL", "ar": "فاشل"},
    Outcome.ERROR: {"en": "ERROR", "ar": "خطأ"},
    Outcome.INCONCLUSIVE: {"en": "INCONCLUSIVE", "ar": "غير حاسم"},
}


def _pick(entry: dict[str, str], lang: Lang | str) -> str:
    code = lang.value if isinstance(lang, Lang) else lang
    return entry.get(code) or entry["en"]


def t(key: str, lang: Lang | str, **params: object) -> str:
    text = _pick(STRINGS[key], lang)
    return text.format(**params) if params else text


def verdict_label(verdict: Verdict, lang: Lang | str) -> str:
    return _pick(VERDICT_LABELS[verdict], lang)


def category_label(category: Category, lang: Lang | str) -> str:
    return _pick(CATEGORY_LABELS[category], lang)


def expected_label(expected: ExpectedAction, lang: Lang | str) -> str:
    return _pick(EXPECTED_LABELS[expected], lang)


def outcome_label(outcome: Outcome, lang: Lang | str) -> str:
    return _pick(OUTCOME_LABELS[outcome], lang)


def format_rate(value: float | None, lang: Lang | str) -> str:
    return t("na", lang) if value is None else f"{value:.1f}%"


def format_ms(value: float | None, lang: Lang | str) -> str:
    return t("na", lang) if value is None else f"{value:.1f} ms"
