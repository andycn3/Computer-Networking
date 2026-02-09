package ca.ubc.cs.cs317.dnslookup;

import java.net.*;
import java.util.*;
import java.io.*;

import static ca.ubc.cs.cs317.dnslookup.DNSMessage.MAX_DNS_MESSAGE_LENGTH;

public class DNSLookupService {

    public static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    private static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new Random();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param verbose    A DNSVerbosePrinter listener object with methods to be called at key events in the query
     *                   processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Answers one question.  If there are valid (not expired) results in the cache, returns these results.
     * Otherwise it chooses the best nameserver to query, retrieves results from that server
     * (using individualQueryProcess which adds all the results to the cache) and repeats until either:
     *   the cache contains an answer to the query, or
     *   the cache contains an answer to the query that is a CNAME record rather than the requested type, or
     *   every "best" nameserver in the cache has already been tried.
     *
     *  @param question Host name and record type/class to be used for the query.
     */
    public Collection<ResourceRecord> iterativeQuery(DNSQuestion question)
            throws DNSErrorException {
        Set<ResourceRecord> ans = new HashSet<>();
        Set<InetAddress> triedServerIPs = new HashSet<>();

        while (true) {
            ans.clear();
            ans.addAll(cache.getCachedResults(question));
            if (!ans.isEmpty()) {
                return ans;
            }
            List<ResourceRecord> bestNS = cache.getBestNameservers(question);
            if (bestNS.isEmpty()) {
                return ans;
            }
            List<ResourceRecord> nsWithIPs = cache.filterByKnownIPAddress(bestNS);

            if (nsWithIPs.isEmpty()) {
                boolean learnedAnyIP = false;
                for (ResourceRecord ns : bestNS) {
                    String nsHost = ns.getTextResult();
                    DNSQuestion nsA = DNSCache.AQuestion(nsHost);
                    Collection<ResourceRecord> nsAResults =
                            getResultsFollowingCNames(nsA, MAX_INDIRECTION_LEVEL_NS);

                    if (nsAResults != null && !nsAResults.isEmpty()) {
                        learnedAnyIP = true;
                        break;
                    }
                }
                if (!learnedAnyIP) {
                    return ans;
                }

                nsWithIPs = cache.filterByKnownIPAddress(bestNS);
            }

            boolean queriedSomeoneNew = false;

            for (ResourceRecord nsA : nsWithIPs) {
                InetAddress serverIP = nsA.getInetResult();
                if (serverIP == null) continue;
                if (triedServerIPs.contains(serverIP)) continue;
                triedServerIPs.add(serverIP);
                queriedSomeoneNew = true;
                Set<ResourceRecord> resp = individualQueryProcess(question, serverIP);
                if (resp != null) {
                    break;
                }
            }
            if (!queriedSomeoneNew) {
                return ans;
            }
        }
    }

    /**
     * Examines a set of resource records to see if any of them are an answer to the given question.
     *
     * @param rrs       The set of resource records to be examined
     * @param question  The DNS question
     * @return          true if the collection of resource records contains an answer to the given question.
     */
    private boolean containsAnswer(Collection<ResourceRecord> rrs, DNSQuestion question) {
        for (ResourceRecord rr : rrs) {
            if (rr.getQuestion().equals(question) && rr.getRecordType() == question.getRecordType()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds all the results for a specific question. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting resource records of the indicated type.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws DNSErrorException If the number CNAME redirection levels exceeds the value set in
     *                           maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getResultsFollowingCNames(DNSQuestion question, int maxIndirectionLevels)
            throws DNSErrorException {

        if (maxIndirectionLevels < 0) throw new DNSErrorException("CNAME indirection limit exceeded");

        Collection<ResourceRecord> directResults = iterativeQuery(question);
        if (containsAnswer(directResults, question)) {
            return directResults;
        }

        Set<ResourceRecord> newResults = new HashSet<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getResultsFollowingCNames(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Handles the process of sending an individual DNS query with a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     *
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     *
     * The method verbose.printQueryToSend() must be called every time a new query message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of all resource records
     * received in the response.
     * @throws DNSErrorException if the Rcode in the response is non-zero
     */
    public Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server)
            throws DNSErrorException {
        DNSMessage query = buildQuery(question);
        int txId = query.getID();
        byte[] out = query.getUsed();
        DatagramPacket request = new DatagramPacket(out, out.length, server, DEFAULT_DNS_PORT);

        for (int attempt = 0; attempt < MAX_QUERY_ATTEMPTS; attempt++) {
            verbose.printQueryToSend("UDP", question, server, txId);

            try {
                socket.send(request);

                while (true) {
                    byte[] inBuf = new byte[MAX_DNS_MESSAGE_LENGTH];
                    DatagramPacket reply = new DatagramPacket(inBuf, inBuf.length);

                    socket.receive(reply);

                    byte[] data = reply.getData();
                    int len = reply.getLength();
                    DNSMessage candidate = new DNSMessage(data, len);
                    if (!candidate.getQR()) continue;
                    if (candidate.getID() != txId) continue;

                    if (candidate.getQDCount() != 1) continue;
                    DNSQuestion receivedQ = candidate.getQuestion();
                    if (!question.equals(receivedQ)) continue;

                    DNSMessage response = new DNSMessage(data, len);

                    try {
                        return processResponse(response);
                    } catch (DNSReplyTruncatedException e) {
                        return tcpFallback(query, question, server);
                    }
                }

            } catch (SocketTimeoutException e) {

            } catch (IOException e) {

            }
        }
        return null;
    }

    private Set<ResourceRecord> tcpFallback(DNSMessage originalQuery, DNSQuestion question, InetAddress server)
            throws DNSErrorException {

        byte[] msg = originalQuery.getUsed();
        int txId = originalQuery.getID();

        verbose.printQueryToSend("TCP", question, server, txId);

        try (Socket s = new Socket(server, DEFAULT_DNS_PORT)) {
            s.setSoTimeout(SO_TIMEOUT);

            DataOutputStream dos = new DataOutputStream(s.getOutputStream());
            DataInputStream dis = new DataInputStream(s.getInputStream());

            dos.writeShort(msg.length);
            dos.write(msg);
            dos.flush();

            int respLen = dis.readUnsignedShort();
            byte[] resp = new byte[respLen];
            dis.readFully(resp);

            DNSMessage response = new DNSMessage(resp, respLen);

            try {
                return processResponse(response);
            } catch (DNSReplyTruncatedException e) {
                return null;
            }
        } catch (IOException e) {
            return null;
        }
    }



    /**
     * Creates a DNSMessage containing a DNS query.
     * A random transaction ID must be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the message's buffer's position (`message.buffer.position`) must be equivalent
     * to the size of the query data.
     *
     * @param question    Host name and record type/class to be used for the query.
     * @return The DNSMessage containing the query.
     */
    public DNSMessage buildQuery(DNSQuestion question) {
        short txId = (short) random.nextInt(0x10000);

        DNSMessage message = new DNSMessage(txId);
        message.setQR(false);
        message.setOpcode(0);
        message.setAA(false);
        message.setTC(false);
        message.setRD(false);
        message.setRA(false);

        message.addQuestion(question);

        return message;
    }

    /**
     * Parses and processes a response received by a nameserver.
     *
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     *
     * If the message has been truncated (the TC bit in the header is 1) then ignores the content of the message and
     * throws a DNSReplyTruncatedException.
     *
     * Adds all resource records found in the response message to the cache.
     * Calls methods in the verbose object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param message The DNSMessage received from the server.
     * @return A set of all resource records received in the response.
     * @throws DNSErrorException if the Rcode value in the reply header is non-zero
     * @throws DNSReplyTruncatedException if the TC bit is 1 in the reply header
     */
    public Set<ResourceRecord> processResponse(DNSMessage message) throws DNSErrorException, DNSReplyTruncatedException {
        int txId = message.getID();
        boolean authoritative = message.getAA();
        boolean tc = message.getTC();
        int rcode = message.getRcode();

        verbose.printResponseHeaderInfo(txId, authoritative, tc, rcode);

        if (rcode != 0) {
            throw new DNSErrorException("DNS Error: RCODE = " + rcode);
        }
        if (tc) {
            throw new DNSReplyTruncatedException("DNS reply truncated (TC=1)");
        }
        Set<ResourceRecord> records = new HashSet<>();
        for (int i = 0; i < message.getQDCount(); i++) {
            message.getQuestion();
        }
        int an = message.getANCount();
        verbose.printAnswersHeader(an);
        for (int i = 0; i < an; i++) {
            ResourceRecord rr = message.getRR();
            if (rr != null) {
                cache.addResult(rr);
                records.add(rr);
                verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClass().getCode());
            }
        }
        int ns = message.getNSCount();
        verbose.printNameserversHeader(ns);
        for (int i = 0; i < ns; i++) {
            ResourceRecord rr = message.getRR();
            if (rr != null) {
                cache.addResult(rr);
                records.add(rr);
                verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClass().getCode());
            }
        }
        int ar = message.getARCount();
        verbose.printAdditionalInfoHeader(ar);
        for (int i = 0; i < ar; i++) {
            ResourceRecord rr = message.getRR();
            if (rr != null) {
                cache.addResult(rr);
                records.add(rr);
                verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClass().getCode());
            }
        }

        return records;
    }

    public static class DNSErrorException extends Exception {
        public DNSErrorException(String msg) {
            super(msg);
        }
    }

    public static class DNSReplyTruncatedException extends Exception {
        public DNSReplyTruncatedException(String msg) {
            super(msg);
        }
    }
}
