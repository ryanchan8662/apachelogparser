import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.HashSet;


import java.util.Locale;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Display {
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_BLACK = "\u001B[30m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_PURPLE = "\u001B[35m";
    private static final String ANSI_CYAN = "\u001B[36m";
    private static final String ANSI_WHITE = "\u001B[37m";
    public static void main (String[] args) throws FileNotFoundException, IOException, InterruptedException {
        String defaultFile = "access.log";
        String systemSlash = "/";
        boolean ignoreBots = false;
        String fileName = defaultFile;
        if (args.length != 0) { // if parameters were specified
            if (args[0].equals("-i")) { // if first parameter is ignoreBots
                ignoreBots = true; // set ignoreBots accordingly
                if (args.length > 1) { // and if two parameters or more, set second as fileName
                    fileName = args[1];
                }
            }
            else { // if (potential) second parameter is ignoreBots
                fileName = args[0]; // set requested file name
                if (args.length > 1 && (args[1].equals("-i"))) { // if second parameter is ignoreBots
                    ignoreBots = true;
                }
            }
        }
        System.out.println("~ File name set as " + fileName + " and " + (ignoreBots ? ("ignoring") : ("including")) + " non-page traffic");
        String currentPath = System.getProperty("user.dir");

        System.out.println("Opening " + currentPath + systemSlash + fileName);
        
        Scanner input = new Scanner(new File(currentPath + systemSlash + "display.conf")); // scanner to configuration file
        
        HashMap<String, ArrayList<Signature>> entries = new HashMap<String, ArrayList<Signature>>();
        long lastUpdate = 0L;
        int total = 0;

        String[] validDirectories;
        String[] validRequests = {"GET"};
        float cutoff = 1.0f;

        // generate list of allowed/valid directories and requests, requests for anything else are considered malicious
        // use display.conf in standard syntax for configuration formats
        {
            ArrayList<String> tempValidDirectories = new ArrayList<String>();
            ArrayList<String> tempValidRequests = new ArrayList<String>();
            try {
                while (input.hasNext()) {
                    String[] line = input.nextLine().replaceAll(" ", "").split(":");
                    if (line[0].equals("ValidDirectory")) tempValidDirectories.add(line[1].replace("\"", ""));
                    else if (line[0].equals("ValidRequest")) tempValidRequests.add(line[1].replace("\"", ""));
                    else if (line[0].equals("Threshold")) {
                        cutoff = (float) Integer.parseInt(line[1].replace("\"", "").substring(0, 2));
                    } else if (line[0].equals("LastModified")) lastUpdate = Long.parseLong(line[1].replace("\"", ""));
                }
            } catch (Exception e) {
                System.out.println("Configuration file may be incorrect. Check syntax and run again.");
                System.exit(1);
            }
            
            validDirectories = new String[tempValidDirectories.size()];
            validRequests = new String[tempValidRequests.size()];

            for (int i = 0; i < validDirectories.length; i++) validDirectories[i] = tempValidDirectories.get(i);

            for (int i = 0; i < validRequests.length; i++) validRequests[i] = tempValidRequests.get(i);
        }
        System.out.println("Threshold: " + cutoff);

        input = new Scanner(new File(currentPath + systemSlash + fileName)); // set scanner file to log file

        while (input.hasNext()) { // process all lines in log file
            Signature currentSignature = splitRequest(input.nextLine(), lastUpdate);
            if (currentSignature != null) { // if entries are after cutoff or no cutoff specified
                total++;
                String clientIp = currentSignature.clientIp();
                ArrayList<Signature> pastRequests;
                
                if (entries.containsKey(clientIp)) { // if entries already exists, simply add to existing arraylist
                    entries.get(clientIp).add(currentSignature); // add to existing list of clients under IP

                } else { // if entries do not exist
                    pastRequests = new ArrayList<Signature>(); // create new IP listing
                    pastRequests.add(currentSignature);
                    entries.put(clientIp, pastRequests); // add listing to hashmap
                }
            } // if before cutoff time, omit from addition
        }
        
        

        

        System.out.println("Unique IP entries:");
        Iterator<String> uniques = entries.keySet().iterator(); // iterator of all keys (IPs) within the map
        ArrayList<Location> locationInfo = new ArrayList<Location>();
        while (uniques.hasNext()) {
            HttpResponse<String> response = requestIPs(uniques);
            locationInfo.addAll(processResponse(response)); // add 100-max list to total list
        }
        
        Iterator<Location> ipList = locationInfo.iterator();

        HashSet<String> badIPs = new HashSet<String>();
        HashSet<String> badDirectories = new HashSet<String>();

        while (ipList.hasNext()) {
            Location currentLocation = ipList.next();
            String currentIp = currentLocation.ip(); // get current IP iteration


            ArrayList<Signature> ipListings = entries.get(currentIp); // get all request listings of current IP
            System.out.println(ANSI_GREEN + "~~ " + currentLocation + ":" + ANSI_RESET);
            Iterator<Signature> requests = ipListings.iterator();
            
            int totalRequests = 0;
            int badRequests = 0;
            while (requests.hasNext()) {
                Signature currentRequest = requests.next();
                System.out.print("| ");
                boolean responseValid = false;
                totalRequests++;
                String directory = currentRequest.requestDirectory();

                for (int i = 0; i < validDirectories.length; i++) {
                    if (directory.length() >= validDirectories[i].length() &&  directory.substring(0, validDirectories[i].length()).equals(validDirectories[i])) {
                        responseValid = true;
                    }
                }
                if (directory.equals("/")) responseValid = true;

                {
                    String requestType = currentRequest.requestDirectory();
                    for (int i = 0; i < validRequests.length; i++) {
                        if (requestType.equals(validRequests[i])) {
                            responseValid = true;
                        }
                    }
                }
                
                if (responseValid) {
                    System.out.println(currentRequest);
                } else {
                    System.out.println(ANSI_YELLOW + currentRequest + ANSI_RESET); // yellow lines for invalid requests
                    badRequests++;
                    if (currentRequest.responseType() == 200) {
                        String[] dirName = directory.split("[/?]");
                        badDirectories.add(dirName.length == 1 ? null : dirName[1]);
                    }
                }
            }
            float temp = ((float) badRequests/totalRequests)*100; // sketchiness percentage for each IP
            if (temp >= cutoff) badIPs.add(currentIp);
            System.out.printf("%s~~ Bad traffic: [%.1f%%]%s%n%n", ANSI_GREEN, temp, ANSI_RESET); // score of analysed IP
        }
        System.out.print(ANSI_RED + "There were " + total + " total requests"); // print log overview, statement continued into EditConf constructor

        {
            EditConf rObj = new EditConf(badIPs, badDirectories, systemSlash);
        }
    }

    /**
     * @param request Apache log request in the specified format - refer to codebase
     * @param lastUpdate Epoch time of last update - if non-0, only update if entry is beyond time
     * @return Signature object containing applicable information
     */
    private static Signature splitRequest (String request, long lastUpdate) {
        // [*IP] - - [*DD/MMM/YYYY:HH:MM:SS +0000] "[REQUEST] [/directory] [protocol]" [*RESPONSE] [*SIZE] "[URI]" "[*User Agent]"
        String[] current = request.split("\"");
        String[] requestDetails = current[0].split(" ");
        // turn date/time format into epoch time
        long epoch = 0;
        {
            String clientString = requestDetails[3].substring(1, 21) + ".000 UTC"; // get substring and add elements
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd/MMM/yyy:HH:mm:ss.SSS zzz", Locale.ENGLISH); // store date format
            epoch = ZonedDateTime.parse(clientString, dtf).toInstant().toEpochMilli(); // translate into epoch time
        }
        if (epoch < lastUpdate) {
            return (null);
        } // return null if entry before cutoff specified
        // otherwise, continue with Signature initialisation

        String[] requestAccess  = current[1].split(" ");
        String[] responseDetails = current[2].split(" ");

        /* for debugging data types and array boundaries

        String clientIp = requestDetails[0];
        long requestTime = epoch;
        String requestType = requestAccess[0];
        String requestDirectory = requestAccess.length > 1 ? requestAccess[1] : "-";
        int responseType = Integer.parseInt(responseDetails[1]);
        int responseSize = Integer.parseInt(responseDetails[2]);
        String userAgent = current[5];

        */

        Signature currentRequest = new Signature(requestDetails[0], epoch, requestAccess[0], requestAccess.length > 1 ? requestAccess[1] : "-", // <-- only record when a valid request has been
        Integer.parseInt(responseDetails[1]), Integer.parseInt(responseDetails[2]), current[5]);

        return (currentRequest);
    }

    private static HttpResponse<String> requestIPs (Iterator<String> ips) throws IOException, InterruptedException {
        String requestBody = "[";
        int counter = 0;
        while(ips.hasNext() && counter < 100) {
            // {"query": "[variable]"}
            
            requestBody += "{\"query\":\"" + ips.next() + "\"}"; // add all ips requested to hashmap
            if (ips.hasNext() && counter < 99) requestBody += ",";
            counter++; // limit requests under 100
            
        }
        requestBody += "]"; // if empty, response will be "[]"

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create("http://ip-api.com/batch?fields=8209"))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
        HttpResponse<String> response = client.send(request,HttpResponse.BodyHandlers.ofString());
        return (response);
    }

    private static ArrayList<Location> processResponse (HttpResponse<String> response) {
        // [{"countryCode":"US","city":"Dublin","query":"3.144.93.248"},{"countryCode":"US","city":"Mountain View","query":"66.249.72.239"}]
        String[] responseStrings = response.body().split("[{}]");
        ArrayList<Location> result = new ArrayList<Location>();
        for (int i = 1; i < responseStrings.length; i+=2) { // skip by every other string, to start on first chunk of data
            String[] items = responseStrings[i].split("\"");
            Location currentIp;

            if (items.length > 11) currentIp = new Location(items[11], items[7], items[3]); // if public IP
                
            else currentIp = new Location(items[3], "local", "local"); // if private LAN IP

            result.add(currentIp);
        }
        return (result);
    }
}
