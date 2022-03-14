

public class Location {

    private String ip;
    private String city;
    private String country;

    public Location (String ip, String city, String country) {
        this.ip = ip; this.city = city; this.country = country;
    }

    public String ip () { return (this.ip); }

    public String city () { return (this.city); }

    public String country () { return (this.country); }

    @Override
    public String toString () {
        return (this.ip + " from " + this.city + ", " + this.country);
    }
}
