package com.packetanalyzer.parser;

public class SniExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int readUint24BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 16) | ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
    }

    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        if (length < 9) return false;
        
        if (payload[offset] != CONTENT_TYPE_HANDSHAKE) return false;
        
        int version = readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;
        
        int recordLength = readUint16BE(payload, offset + 3);
        if (recordLength > length - 5) return false;
        
        if (payload[offset + 5] != HANDSHAKE_CLIENT_HELLO) return false;
        
        return true;
    }

    public static String extractTLS(byte[] payload, int startOffset, int length) {
        if (!isTLSClientHello(payload, startOffset, length)) {
            return null;
        }
        
        int offset = startOffset + 5;
        
        int handshakeLength = readUint24BE(payload, offset + 1);
        offset += 4;
        
        offset += 2; // Client version
        offset += 32; // Random
        
        if (offset >= startOffset + length) return null;
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;
        
        if (offset + 2 > startOffset + length) return null;
        int cipherSuitesLength = readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLength;
        
        if (offset >= startOffset + length) return null;
        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;
        
        if (offset + 2 > startOffset + length) return null;
        int extensionsLength = readUint16BE(payload, offset);
        offset += 2;
        
        int extensionsEnd = offset + extensionsLength;
        if (extensionsEnd > startOffset + length) {
            extensionsEnd = startOffset + length;
        }
        
        while (offset + 4 <= extensionsEnd) {
            int extensionType = readUint16BE(payload, offset);
            int extensionLength = readUint16BE(payload, offset + 2);
            offset += 4;
            
            if (offset + extensionLength > extensionsEnd) break;
            
            if (extensionType == EXTENSION_SNI) {
                if (extensionLength < 5) break;
                
                int sniListLength = readUint16BE(payload, offset);
                if (sniListLength < 3) break;
                
                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = readUint16BE(payload, offset + 3);
                
                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extensionLength - 5) break;
                
                return new String(payload, offset + 5, sniLength);
            }
            
            offset += extensionLength;
        }
        
        return null;
    }

    public static String extractHTTPHost(byte[] payload, int startOffset, int length) {
        if (length < 4) return null;
        
        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
        boolean isHttp = false;
        for (String method : methods) {
            boolean match = true;
            for (int i = 0; i < 4; i++) {
                if (payload[startOffset + i] != (byte) method.charAt(i)) {
                    match = false;
                    break;
                }
            }
            if (match) {
                isHttp = true;
                break;
            }
        }
        
        if (!isHttp) return null;
        
        for (int i = startOffset; i + 6 < startOffset + length; i++) {
            if (Character.toLowerCase((char) payload[i]) == 'h' &&
                Character.toLowerCase((char) payload[i+1]) == 'o' &&
                Character.toLowerCase((char) payload[i+2]) == 's' &&
                Character.toLowerCase((char) payload[i+3]) == 't' &&
                payload[i+4] == ':') {
                
                int start = i + 5;
                while (start < startOffset + length && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }
                
                int end = start;
                while (end < startOffset + length && payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }
                
                if (end > start) {
                    String host = new String(payload, start, end - start);
                    int colonPos = host.indexOf(':');
                    if (colonPos != -1) {
                        host = host.substring(0, colonPos);
                    }
                    return host;
                }
            }
        }
        
        return null;
    }

    public static String extractDNSQuery(byte[] payload, int startOffset, int length) {
        if (length < 12) return null;
        
        int flags = payload[startOffset + 2] & 0xFF;
        if ((flags & 0x80) != 0) return null;
        
        int qdcount = readUint16BE(payload, startOffset + 4);
        if (qdcount == 0) return null;
        
        int offset = startOffset + 12;
        StringBuilder domain = new StringBuilder();
        
        while (offset < startOffset + length) {
            int labelLength = payload[offset] & 0xFF;
            
            if (labelLength == 0) break;
            if (labelLength > 63) break;
            
            offset++;
            if (offset + labelLength > startOffset + length) break;
            
            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, offset, labelLength));
            offset += labelLength;
        }
        
        return domain.length() == 0 ? null : domain.toString();
    }

    public static boolean isQUICInitial(byte[] payload, int startOffset, int length) {
        if (length < 5) return false;
        int firstByte = payload[startOffset] & 0xFF;
        if ((firstByte & 0x80) == 0) return false;
        return true;
    }

    public static String extractQUIC(byte[] payload, int startOffset, int length) {
        if (!isQUICInitial(payload, startOffset, length)) return null;
        
        for (int i = startOffset; i + 50 < startOffset + length; i++) {
            if (payload[i] == 0x01) {
                if (i - startOffset >= 5) {
                    String result = extractTLS(payload, i - 5, length - (i - startOffset) + 5);
                    if (result != null) return result;
                }
            }
        }
        return null;
    }
}
