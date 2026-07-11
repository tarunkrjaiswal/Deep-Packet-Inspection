package com.packetanalyzer.types;

public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC,
    GOOGLE, FACEBOOK, YOUTUBE, TWITTER, INSTAGRAM,
    NETFLIX, AMAZON, MICROSOFT, APPLE, WHATSAPP,
    TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD,
    GITHUB, CLOUDFLARE;

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String lower = sni.toLowerCase();
        
        if (lower.contains("google") || lower.contains("gstatic") || lower.contains("googleapis") || lower.contains("ggpht") || lower.contains("gvt1")) return GOOGLE;
        if (lower.contains("youtube") || lower.contains("ytimg") || lower.contains("youtu.be") || lower.contains("yt3.ggpht")) return YOUTUBE;
        if (lower.contains("facebook") || lower.contains("fbcdn") || lower.contains("fb.com") || lower.contains("fbsbx") || lower.contains("meta.com")) return FACEBOOK;
        if (lower.contains("instagram") || lower.contains("cdninstagram")) return INSTAGRAM;
        if (lower.contains("whatsapp") || lower.contains("wa.me")) return WHATSAPP;
        if (lower.contains("twitter") || lower.contains("twimg") || lower.contains("x.com") || lower.contains("t.co")) return TWITTER;
        if (lower.contains("netflix") || lower.contains("nflxvideo") || lower.contains("nflximg")) return NETFLIX;
        if (lower.contains("amazon") || lower.contains("amazonaws") || lower.contains("cloudfront") || lower.contains("aws")) return AMAZON;
        if (lower.contains("microsoft") || lower.contains("msn.com") || lower.contains("office") || lower.contains("azure") || lower.contains("live.com") || lower.contains("outlook") || lower.contains("bing")) return MICROSOFT;
        if (lower.contains("apple") || lower.contains("icloud") || lower.contains("mzstatic") || lower.contains("itunes")) return APPLE;
        if (lower.contains("telegram") || lower.contains("t.me")) return TELEGRAM;
        if (lower.contains("tiktok") || lower.contains("tiktokcdn") || lower.contains("musical.ly") || lower.contains("bytedance")) return TIKTOK;
        if (lower.contains("spotify") || lower.contains("scdn.co")) return SPOTIFY;
        if (lower.contains("zoom")) return ZOOM;
        if (lower.contains("discord") || lower.contains("discordapp")) return DISCORD;
        if (lower.contains("github") || lower.contains("githubusercontent")) return GITHUB;
        if (lower.contains("cloudflare") || lower.contains("cf-")) return CLOUDFLARE;
        
        return HTTPS;
    }
}
