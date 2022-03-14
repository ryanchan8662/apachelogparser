import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

import java.util.Scanner;
import java.util.spi.LocaleNameProvider;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

public class EditConf {

    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_BLACK = "\u001B[30m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_PURPLE = "\u001B[35m";
    private static final String ANSI_CYAN = "\u001B[36m";
    private static final String ANSI_WHITE = "\u001B[37m";

    public EditConf (HashSet<String> ipList, HashSet<String> requestList, String systemSlash) {
        System.out.print(", " + ipList.size() + " IPs above the tolerated limit and " + requestList.size() + " non-blocked bad requests" + ANSI_RESET);
        System.out.println("");

        Scanner input = new Scanner(System.in);
        System.out.print("\nReview caught requests (y/n)? ");
        String userInput = input.nextLine();

        if (userInput.equals("y")) {
            reviewIPs(ipList);
        }

        System.out.print("Proceed with adding requests to .htaccess (y/n)? ");
        userInput = input.nextLine();
        if (userInput.equals("y")) {
            reviewRequests(requestList);
        }
        try {
            writeFile(ipList, requestList, systemSlash);
        } catch (Exception e) {

        }
        
    }

    private void reviewIPs (HashSet<String> ipList) {
        Iterator<String> ipIterator = ipList.iterator();

        System.out.println("\nCollected IPs: ");
        for (int i = 1; ipIterator.hasNext(); i++) {
            System.out.printf("%s %-15s %s", ANSI_CYAN, ipIterator.next(), ANSI_RESET);
            if (i % 8 == 0) System.out.println();
        }
        System.out.printf("\n");

        System.out.print("\nAdd IPs to remove from list: (enter IPs, separated by a space) ");
        Scanner input = new Scanner(System.in);
        String userInput = input.nextLine();
        if (userInput.length() > 0) {
            String[] toRemove = userInput.split(" +");
            for (String i : toRemove) ipList.remove(i); // remove all entered ips
        }
    }

    private void reviewRequests (HashSet<String> requestList) {
        Iterator<String> requestIterator = requestList.iterator();
        System.out.printf("\nCollected directory requests:\n\n");
        for (int i = 1; requestIterator.hasNext(); i++) {
            String current = requestIterator.next();
            if (current.length() > 15) {
                System.out.printf("%s %-12s%s %s", ANSI_CYAN, current.substring(0, 12), "...", ANSI_RESET);
            } else {
                System.out.printf("%s %-15s %s", ANSI_CYAN, current, ANSI_RESET);
            } if (i % 8 == 0) System.out.println();
        }
    }

    private void writeFile (HashSet<String> ipList, HashSet<String> requestList, String systemSlash) throws FileNotFoundException {
        
        String startComment = "# Fallback resource for React servers - comments in this file denote individual segments";
        String denyComment = "# Deny IPs with a disproportional amount of bad requests";
        String rewriteComment = "# Deny uncaught invalid requested directories";

        int segment = 0; // 0: misc uncategorised 1: start section 2: denies 3: rewrites

        String logLocation = "";

        ArrayList<String> miscStatements = new ArrayList<String>();
        ArrayList<String> startStatements = new ArrayList<String>();
        ArrayList<String> denyStatements = new ArrayList<String>();
        ArrayList<String> rewriteStatements = new ArrayList<String>();

        String currentPath = System.getProperty("user.dir");
        Scanner input = new Scanner(new File(currentPath + systemSlash + ".htaccess"));

        while (input.hasNext()) {
            String currentLine = input.nextLine();
            if (currentLine.length() > 0 && currentLine.charAt(0) == '#') {

                // set sections accordingly depending on header content
                if (currentLine.equals(startComment)) segment = 1;
                else if (currentLine.equals(denyComment)) segment = 2;
                else if (currentLine.equals(rewriteComment)) segment = 3;
                else segment = 0;

            } else { // add content line to buffer
                if (currentLine.length() > 0) {
                    switch (segment) {

                        case (0): miscStatements.add(currentLine); break;
                        case (1): startStatements.add(currentLine); break;
                        case (2): denyStatements.add(currentLine); break;
                        case (3): rewriteStatements.add(currentLine); break;
                        
                    }
                }
            }
        }

        
        String denyStarter = "Deny from ";
        String rewriteRule = "RewriteRule .* - [F,L]";
        String rewriteCondRequest = "RewriteCond %{THE_REQUEST} \"^.*";
        String rewriteCondUA = "RewriteCond %{HTTP_USER_AGENT} \"^.*";
        String rewriteCondCap = ".*$\"";

        String testWrite = "";

        Iterator<String> badIP = ipList.iterator();

        // write for React service block and starter block
        testWrite += "\n\n\n" + startComment + "\n\n";
        Iterator<String> startIterator = startStatements.iterator();
        while (startIterator.hasNext()) {
            testWrite += startIterator.next() + "\n";
        }

        testWrite += "\n\n\n" + denyComment + "\n\n";

        // copy old deny lines
        Iterator<String> existingDenies = denyStatements.iterator();
        while (existingDenies.hasNext()) {
            testWrite += existingDenies.next() + "\n";
        }

        // write bad request lines for .htaccess
        while (badIP.hasNext()) {
            testWrite += denyStarter + badIP.next() + "\n";
        }


        testWrite += "\n\n\n" + rewriteComment + "\n\n";

        // copy old rewrite lines
        Iterator<String> existingRewrites = rewriteStatements.iterator();
        while (existingRewrites.hasNext()) {
            testWrite += existingRewrites.next() + "\n";
        }

        Iterator<String> badRequests = requestList.iterator();
        // write new rewrite lines
        while (badRequests.hasNext()) {
            testWrite += rewriteCondRequest + badRequests.next() + rewriteCondCap + "\n" + rewriteRule + "\n";
        }
        

        testWrite += "\n\n\n" + "# Misc uncategorised comments" + "\n\n";
        Iterator<String> miscIterator = miscStatements.iterator();
        while (miscIterator.hasNext()) {
            testWrite += miscIterator.next() + "\n";
        }

        System.out.println(testWrite);
    }

    
}
