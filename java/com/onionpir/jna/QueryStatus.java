package com.onionpir.jna;

/** Status of an in-flight ticket from {@link OnionPirQueue}. */
public enum QueryStatus {
    QUEUED(0),
    PROCESSING(1),
    DONE(2),
    ERROR(3),
    NOT_FOUND(4);

    public final int code;
    QueryStatus(int code) { this.code = code; }

    static QueryStatus fromCode(int code) {
        for (QueryStatus s : values()) if (s.code == code) return s;
        return NOT_FOUND;
    }
}
