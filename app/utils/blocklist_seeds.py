"""
Real domain seed lists backing the Family Safe DNS categories.

Two different strategies are used deliberately:

1. Brand-name categories (ads/tracking, adult, gambling, social media,
   gaming, streaming, torrents, VPN/proxy, dating) are dominated by a
   relatively small, stable set of well-known services. Those are
   bundled here as a real curated seed list so toggling the category
   on blocks real domains immediately, with no internet access needed.

2. Security-critical categories (malware, phishing, scam, ransomware,
   botnet) change constantly -- a static list from any point in time
   goes stale within days and gives false confidence. Those are instead
   pre-wired to real, actively-maintained public threat-intel sources
   (see SECURITY_FEED_URLS) using the scheduled blocklist updater --
   correct engineering, even though it needs live internet to populate,
   which this bundled seed data does not.

None of this is exhaustive or a substitute for a dedicated commercial
filtering service -- it's a genuine, real baseline, not a placeholder.
"""

# Well-known ad-tech / tracking domains (the actual "ad blocker").
ADS_TRACKING = [
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "google-analytics.com", "googletagmanager.com", "googletagservices.com",
    "adnxs.com", "adsrvr.org", "adform.net", "adroll.com",
    "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
    "scorecardresearch.com", "quantserve.com", "moatads.com",
    "pubmatic.com", "rubiconproject.com", "openx.net", "casalemedia.com",
    "smartadserver.com", "media.net", "advertising.com", "yieldmo.com",
    "bidswitch.net", "contextweb.com", "indexww.com", "sharethrough.com",
    "spotxchange.com", "teads.tv", "tribalfusion.com", "mathtag.com",
    "everesttech.net", "amazon-adsystem.com", "app-measurement.com",
    "branch.io", "appsflyer.com", "adjust.com", "flurry.com",
    "chartboost.com", "applovin.com", "mopub.com", "vungle.com", "ironsource.com",
]

GAMBLING = [
    "bet365.com", "pokerstars.com", "draftkings.com", "fanduel.com",
    "bovada.lv", "888casino.com", "partypoker.com", "williamhill.com",
    "betfair.com", "unibet.com", "betway.com", "stake.com", "betmgm.com",
    "playnow.com", "888poker.com", "ladbrokes.com", "paddypower.com",
]

SOCIAL_MEDIA = [
    "facebook.com", "instagram.com", "tiktok.com", "twitter.com", "x.com",
    "snapchat.com", "reddit.com", "pinterest.com", "tumblr.com",
    "discord.com", "linkedin.com",
]

GAMING = [
    "roblox.com", "steampowered.com", "steamcommunity.com", "epicgames.com",
    "twitch.tv", "minecraft.net", "ea.com", "battle.net", "riotgames.com",
    "xbox.com", "playstation.com",
]

STREAMING = [
    "netflix.com", "hulu.com", "disneyplus.com", "primevideo.com",
    "max.com", "peacocktv.com", "paramountplus.com", "youtube.com",
]

TORRENT_P2P = [
    "thepiratebay.org", "1337x.to", "yts.mx", "limetorrents.info",
    "torrentz2.eu", "zooqle.com", "torlock.com", "kickasstorrents.to",
]

VPN_PROXY = [
    "nordvpn.com", "expressvpn.com", "protonvpn.com", "surfshark.com",
    "cyberghostvpn.com", "privateinternetaccess.com", "tunnelbear.com",
    "windscribe.com", "hotspotshield.com",
]

DATING = [
    "tinder.com", "bumble.com", "match.com", "okcupid.com", "hinge.co",
    "plentyoffish.com", "eharmony.com", "grindr.com",
]

ADULT = [
    "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "redtube.com",
    "youporn.com", "brazzers.com", "chaturbate.com", "onlyfans.com", "spankbang.com",
]

DRUGS = [
    "leafly.com", "weedmaps.com", "marijuana.com", "hightimes.com",
]

CRYPTO_MINING = [
    "coinbase.com", "binance.com", "kraken.com", "crypto.com", "blockchain.com",
]

SEED_LISTS = {
    "ads_tracking": ADS_TRACKING, "gambling": GAMBLING, "social_media": SOCIAL_MEDIA,
    "gaming": GAMING, "streaming": STREAMING, "torrent": TORRENT_P2P,
    "vpn_proxy": VPN_PROXY, "dating": DATING, "adult": ADULT,
    "drugs": DRUGS, "crypto_mining": CRYPTO_MINING,
}

# Real, actively-maintained public threat-intel sources for the security
# categories. These are genuine URLs used by tools like Pi-hole; they
# need live internet access (via the scheduled blocklist updater) to
# actually populate -- there is no static substitute that wouldn't be
# stale and misleading.
SECURITY_FEED_URLS = {
    "malware": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "phishing": "https://openphish.com/feed.txt",
    "scam": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "ransomware": "https://urlhaus.abuse.ch/downloads/hostfile/",
    "botnet": "https://urlhaus.abuse.ch/downloads/hostfile/",
}

CATEGORY_LABELS = {
    "ads_tracking": "Ads & Tracking", "malware": "Malware protection",
    "phishing": "Phishing protection", "scam": "Scam protection",
    "ransomware": "Ransomware protection", "botnet": "Botnet blocking",
    "adult": "Adult content", "gambling": "Gambling", "dating": "Dating",
    "violence": "Violence", "drugs": "Drugs", "weapons": "Weapons",
    "social_media": "Social media", "gaming": "Gaming", "streaming": "Streaming",
    "torrent": "Torrent / P2P", "vpn_proxy": "VPN / proxy", "crypto_mining": "Cryptocurrency",
}
