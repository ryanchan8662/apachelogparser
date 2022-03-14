import java.util.Date;

public class Signature {
    private String clientIp;
    private long requestTime;
    private String requestType;
    private String requestDirectory;
    private int responseType;
    private int responseSize;
    private String userAgent;
    public Signature (String clientIp, long requestTime, String requestType, String requestDirectory, int responseType, int responseSize, String userAgent) {
        this.clientIp = clientIp; this.requestTime = requestTime; this.requestType = requestType; this.requestDirectory = requestDirectory;
        this.responseType = responseType; this.responseSize = responseSize; this.userAgent = userAgent;
    }
    
    /**
     * @return String Stored IP
     */
    public String clientIp () { return (this.clientIp); }

    /**
     * @return long Time of request, epoch time
     */
    public long requestTime () { return (this.requestTime); }

    /**
     * @return String HTTP request type, typically get
     */
    public String requestType () { return (this.requestType); }

    /**
     * @return String Directory of requested content
     */
    public String requestDirectory () { return (this.requestDirectory); }

    /**
     * @return int HTTP response code
     */
    public int responseType () { return (this.responseType); }

    /**
     * @return int Size of response packet
     */
    public int responseSize () { return (this.responseSize); }

    /**
     * @return String Client UA
     */
    public String userAgent () { return (this.userAgent); }

    @Override
    public String toString () {
        String result = "";
        Date requestDate = new Date(this.requestTime);
        result += requestDate.toString() + " " + this.responseType + "-" + this.requestType + " to " + this.requestDirectory;
        return (result);
    }
}
