from .models import AppProfile, Category, DomainProbe, ExpectedAction

BUILTIN_PROFILES: dict[str, AppProfile] = {
    "sinko_safesearch": AppProfile(
        id="sinko_safesearch",
        name="SafeSearch & Restricted Mode Enforcer",
        name_ar="فرض البحث الآمن ووضع التقييد",
        description="Audits DNS CNAME/VIP rewriting for Google, YouTube, Bing, and DuckDuckGo SafeSearch.",
        probes=[
            DomainProbe(
                domain="www.google.com",
                category=Category.SAFE_SEARCH,
                expected=ExpectedAction.SAFESEARCH,
                expected_cname_markers=["forcesafesearch.google.com", "216.239.38.120"],
            ),
            DomainProbe(
                domain="www.youtube.com",
                category=Category.SAFE_SEARCH,
                expected=ExpectedAction.SAFESEARCH,
                expected_cname_markers=[
                    "restrict.youtube.com",
                    "restrictmoderate.youtube.com",
                    "216.239.38.120",
                    "216.239.38.119",
                ],
            ),
            DomainProbe(
                domain="www.bing.com",
                category=Category.SAFE_SEARCH,
                expected=ExpectedAction.SAFESEARCH,
                expected_cname_markers=["strict.bing.com", "204.79.197.220"],
            ),
            DomainProbe(
                domain="duckduckgo.com",
                category=Category.SAFE_SEARCH,
                expected=ExpectedAction.SAFESEARCH,
                expected_cname_markers=["safe.duckduckgo.com"],
            ),
        ],
    ),
    "youtube_app": AppProfile(
        id="youtube_app",
        name="YouTube Mobile & Smart TV",
        name_ar="تطبيق يوتيوب والمنصات الذكية",
        description="Simulates YouTube video delivery, DoubleClick ad pre-rolls, and watch-history beacons.",
        probes=[
            DomainProbe(
                domain="i.ytimg.com", category=Category.CORE_SERVICE, expected=ExpectedAction.ALLOW
            ),
            DomainProbe(
                domain="yt3.ggpht.com",
                category=Category.CORE_SERVICE,
                expected=ExpectedAction.ALLOW,
            ),
            DomainProbe(
                domain="googleads.g.doubleclick.net",
                category=Category.ADS,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="pagead2.googlesyndication.com",
                category=Category.ADS,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="ad.doubleclick.net", category=Category.ADS, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="s.youtube.com", category=Category.TELEMETRY, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="video-stats.l.google.com",
                category=Category.TELEMETRY,
                expected=ExpectedAction.BLOCK,
            ),
        ],
    ),
    "tiktok_snap_social": AppProfile(
        id="tiktok_snap_social",
        name="TikTok, Snapchat & Instagram Reels",
        name_ar="تيك توك وسناب شات وتطبيقات التواصل",
        description="Simulates short-form video feeds, social graph endpoints, and mobile ad-tracking SDKs.",
        probes=[
            DomainProbe(
                domain="api16-normal-c-useast1a.tiktokv.com",
                category=Category.SOCIAL,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="v16-webapp-prime.tiktok.com",
                category=Category.SOCIAL,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="ads.tiktok.com", category=Category.ADS, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="log.byteoversea.com",
                category=Category.TELEMETRY,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="app.snapchat.com", category=Category.SOCIAL, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="sc-analytics.appspot.com",
                category=Category.TELEMETRY,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="graph.instagram.com",
                category=Category.SOCIAL,
                expected=ExpectedAction.BLOCK,
            ),
        ],
    ),
    "roblox_gaming": AppProfile(
        id="roblox_gaming",
        name="Roblox & Online Gaming",
        name_ar="روبلوكس والألعاب الإلكترونية",
        description="Tests bedtime/study-hour game blocking (Roblox, Epic, Discord) and game telemetry.",
        probes=[
            DomainProbe(
                domain="www.roblox.com", category=Category.GAMING, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="games.roblox.com", category=Category.GAMING, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="apis.roblox.com", category=Category.GAMING, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="ecsv2.roblox.com",
                category=Category.TELEMETRY,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="discord.com", category=Category.SOCIAL, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="gateway.discord.gg", category=Category.GAMING, expected=ExpectedAction.BLOCK
            ),
        ],
    ),
    "smart_tv_oem": AppProfile(
        id="smart_tv_oem",
        name="Smart TV & IoT ACR Telemetry",
        name_ar="تتبع وإعلانات الشاشات الذكية",
        description="Simulates LG webOS, Samsung Tizen, and Xiaomi MIUI background ad/ACR telemetry.",
        probes=[
            DomainProbe(
                domain="ad.lgappstv.com", category=Category.ADS, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="samsungads.com", category=Category.ADS, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="gpm.samsungqbe.com",
                category=Category.TELEMETRY,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="api.ad.xiaomi.com", category=Category.ADS, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="data.mistat.xiaomi.com",
                category=Category.TELEMETRY,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="tracking.miui.com",
                category=Category.TELEMETRY,
                expected=ExpectedAction.BLOCK,
            ),
        ],
    ),
    "sinko_family_shield": AppProfile(
        id="sinko_family_shield",
        name="Sinko Family Shield & Study Guard",
        name_ar="درع سينكو العائلي وحماية الدراسة",
        description="Verifies adult/gambling blocks while ensuring school, coding, and educational sites work.",
        probes=[
            DomainProbe(
                domain="pornhub.com",
                category=Category.PARENTAL_RESTRICTED,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="xvideos.com",
                category=Category.PARENTAL_RESTRICTED,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="bet365.com",
                category=Category.PARENTAL_RESTRICTED,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="stake.com",
                category=Category.PARENTAL_RESTRICTED,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="www.wikipedia.org",
                category=Category.CORE_SERVICE,
                expected=ExpectedAction.ALLOW,
            ),
            DomainProbe(
                domain="www.khanacademy.org",
                category=Category.CORE_SERVICE,
                expected=ExpectedAction.ALLOW,
            ),
            DomainProbe(
                domain="scratch.mit.edu",
                category=Category.CORE_SERVICE,
                expected=ExpectedAction.ALLOW,
            ),
            DomainProbe(
                domain="github.com", category=Category.CORE_SERVICE, expected=ExpectedAction.ALLOW
            ),
        ],
    ),
    "ai_chatbots": AppProfile(
        id="ai_chatbots",
        name="AI Chatbots & Homework Helpers",
        name_ar="روبوتات الدردشة بالذكاء الاصطناعي",
        description="AI assistants: reachable by default, blocked by Homework Mode style policies.",
        probes=[
            DomainProbe(
                domain="chatgpt.com", category=Category.AI_CHATBOTS, expected=ExpectedAction.ALLOW
            ),
            DomainProbe(
                domain="gemini.google.com",
                category=Category.AI_CHATBOTS,
                expected=ExpectedAction.ALLOW,
            ),
            DomainProbe(
                domain="claude.ai", category=Category.AI_CHATBOTS, expected=ExpectedAction.ALLOW
            ),
            DomainProbe(
                domain="copilot.microsoft.com",
                category=Category.AI_CHATBOTS,
                expected=ExpectedAction.ALLOW,
            ),
            DomainProbe(
                domain="character.ai", category=Category.AI_CHATBOTS, expected=ExpectedAction.ALLOW
            ),
        ],
    ),
}
