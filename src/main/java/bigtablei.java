package com.yahoo.ycsb.db;

import com.google.common.annotations.VisibleForTesting;
import com.yahoo.ycsb.*;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.Cell;
import org.apache.hadoop.hbase.CellUtil;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.client.ConnectionFactory;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.client.Table;
import org.apache.hadoop.hbase.util.Bytes;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class BigTableI extends com.yahoo.ycsb.DB {
    private Configuration config = HBaseConfiguration.create();
    private static Connection connection = null;
    private Table currentTable = null;

    private String columnFamily = "";
    private byte[] columnFamilyBytes;
    private String iMetaColumnFamily = "i-meta";
    private byte[] iMetaColumnFamilyBytes = Bytes.toBytes(iMetaColumnFamily);

    private int curBulkSize = 0;
    private Map<String, HashMap<String, ByteIterator>> curBulk = new HashMap<>();
    private List<String> prevBulkKeys = new ArrayList<>();
    private int bulkSize;
    private int p;

    private static MessageDigest md;
    private static Mac macInstance;
    private static Cipher encCipher;
    private static Cipher decCipher;
    private static final int BLOOM_FILTER_SIZE = 1024;
    private static final Random RAND = new Random();
    private static final String ENC_KEY = "abcdef1234567890";
    private static final String AUTH_KEY = "1234567890abcdef";
    private static final String ENC_ALG = "AES/ECB/PKCS5Padding";
    private static final String HASH_ALG = "SHA-256";
    private static final String HMAC_ALG = "HmacSHA256";
    private static final String LINK_DATA_DELIMITER = ",";
    private static final int VERIFICATION_QUERIES_POOL_SIZE = 10;
    private static final ExecutorService pool = Executors.newFixedThreadPool(VERIFICATION_QUERIES_POOL_SIZE);

    @Override
    public void init() throws DBException {

        try {
            Properties props = getProperties();

            // init connection
            connection = ConnectionFactory.createConnection(config);
            columnFamily = props.getProperty("columnfamily");
            columnFamilyBytes = Bytes.toBytes(columnFamily);
            currentTable = connection.getTable(TableName.valueOf(com.yahoo.ycsb.workloads.CoreWorkload.table));
            currentTable.getTableDescriptor();

            // init security primitives
            p = Integer.valueOf(props.getProperty("p", "4"));
            bulkSize = Integer.valueOf(props.getProperty("bulkSize", "100"));
            md = MessageDigest.getInstance(HASH_ALG);
            SecretKey ke = new SecretKeySpec(AUTH_KEY.getBytes(), "AES");
            encCipher = Cipher.getInstance(ENC_ALG);
            encCipher.init(Cipher.ENCRYPT_MODE, ke);
            decCipher = Cipher.getInstance(ENC_ALG);
            decCipher.init(Cipher.DECRYPT_MODE, ke);
            SecretKey km = new SecretKeySpec(ENC_KEY.getBytes(), HMAC_ALG);
            macInstance = Mac.getInstance(HMAC_ALG);
            macInstance.init(km);

        }catch(Exception e){
            throw new DBException("Initialization failed !", e);
        }
    }

    @Override
    public Status insert(String table, String key, HashMap<String, ByteIterator> values){
        curBulk.put(key, values);
        curBulkSize++;
        if (curBulkSize < bulkSize) {
            return Status.BATCHED_OK;
        } else {
            Status result = putBulk(curBulk);
            if (result.isOk()) {
                curBulkSize = 0;
                curBulk.clear();
            }
            return result;
        }
    }

    private Status putBulk(Map<String, HashMap<String, ByteIterator>> bulk) {
        List<String> keys = new ArrayList<>(bulk.keySet());
        for (String key : keys) {
            Set<String> linkData = getLinkData(keys, key);
            Status status = insertRow(key, bulk.get(key), linkData);
            if (status == Status.ERROR)
                return Status.ERROR;
        }
        prevBulkKeys = new ArrayList<>(bulk.keySet());
        return Status.OK;
    }

    private Set<String> getLinkData(List<String> bulkKeys, String key) {
        Set<String> result = getNextKeys(bulkKeys, key, p/2);
        if (!prevBulkKeys.isEmpty()) {
            result.addAll(getNextKeys(prevBulkKeys, key, p/2));
        }
        return result;
    }

    private Set<String> getNextKeys(List<String> keys, String key, int keysNum) {
        Set<String> result = new HashSet<>(keysNum);
        while (result.size() < keysNum) {
            String nextKey = keys.get(RAND.nextInt(keys.size()));
            if (!nextKey.equals(key)) {
                result.add(nextKey);
            }
        }
        return result;
    }

    public Status insertRow(String key, HashMap<String, ByteIterator> values, Set<String> linkData) {
        //System.out.println("Setting up put for key: " + key);
        Put p = new Put(Bytes.toBytes(key));
        TreeMap<String, String> sortedValues = new TreeMap<>();
        BloomFilter bloomFilter = new BloomFilter(BLOOM_FILTER_SIZE);

        // add data
        for (Map.Entry<String, ByteIterator> entry : values.entrySet()){
            byte[] value = entry.getValue().toArray();
            //System.out.println("Adding field/value " + entry.getKey() + "/" + Bytes.toStringBinary(value) + " to put request");
            p.addColumn(columnFamilyBytes, Bytes.toBytes(entry.getKey()), value);
            sortedValues.put(entry.getKey(), Bytes.toString(value));
            bloomFilter.add(entry.getKey() + Bytes.toString(value));
        }

        // add meta data
        String colFamilyHash = hashFamily(sortedValues);
        String bloomHash = hashBloom(bloomFilter);
        p.addColumn(iMetaColumnFamilyBytes, Bytes.toBytes(columnFamily + "-hash"), Bytes.toBytes(colFamilyHash));
        p.addColumn(iMetaColumnFamilyBytes, Bytes.toBytes(columnFamily + "-bloom"), bloomFilter.toBytes());
        p.addColumn(iMetaColumnFamilyBytes, Bytes.toBytes(columnFamily + "-bloom-hash"), Bytes.toBytes(bloomHash));
        p.addColumn(iMetaColumnFamilyBytes, Bytes.toBytes("row-mac"), Bytes.toBytes(rowMac(key, colFamilyHash, bloomHash)));
        p.addColumn(iMetaColumnFamilyBytes, Bytes.toBytes("link-data"), Bytes.toBytes(encLinkData(linkData)));

        // put row into DB
        try {
            currentTable.put(p);
        } catch (Exception e) {
            return Status.ERROR;
        }

        return Status.OK;
    }

    private static String hashFamily(Map<String, String> sortedValues) {
        try{
            StringBuilder builder = new StringBuilder();
            for (String colName : sortedValues.keySet())
                builder.append(colName).append(sortedValues.get(colName));
            md.update(builder.toString().getBytes());
        }catch(Exception e){
            throw new RuntimeException("Failed to hash column family !");
        }
        return Base64.getEncoder().encodeToString(md.digest());
    }

    private static String hashBloom(BloomFilter bloomFilter){
        try{
            md.update(bloomFilter.toString().getBytes());
        }catch(Exception e){
            throw new RuntimeException("Failed to hash bloom filter !");
        }
        return Base64.getEncoder().encodeToString(md.digest());
    }

    private static String rowMac(String key, String familyHash, String bloomHash){
        return Base64.getEncoder().encodeToString(macInstance.doFinal(Bytes.toBytes(key+familyHash+bloomHash)));
    }

    private static String encLinkData(Set<String> linkData) {
        try {
            return Base64.getEncoder().encodeToString(encCipher.doFinal(serializeLinkData(linkData).getBytes()));
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt linking data");
        }
    }

    private static String serializeLinkData(Set<String> linkData) {
        return linkData.stream().collect(Collectors.joining(","));
    }

    @Override
    public Status read(String table, String key, Set<String> fields, HashMap<String, ByteIterator> result) {
        Result r = getRow(key, fields);

        if (r == null || r.isEmpty()) {
            return Status.NOT_FOUND;
        }

        SortedMap <String, String> sortedColumnValues = getColumns(r, result);

        verifyCorrectness(r, key, sortedColumnValues, fields == null);

        verifyCompleteness(r);

        return Status.OK;
    }

    private Result getRow(String key, Set<String> fields){        
        Get g = new Get(Bytes.toBytes(key));
        if (fields == null){
            g.addFamily(columnFamilyBytes);
        }else{
            for (String field : fields) {
                g.addColumn(columnFamilyBytes, Bytes.toBytes(field));
            }
        }
        g.addFamily(iMetaColumnFamilyBytes);
        try{
            return currentTable.get(g);
        } catch (IOException e) {
            System.err.println("Error doing get: " + e);
            return null;
        }
    }

    private SortedMap<String, String> getColumns(Result row, HashMap<String, ByteIterator> result){
        SortedMap<String, String> columns = new TreeMap<>();
        while (row.advance()){
            Cell c = row.current();
            if (!Bytes.toString(CellUtil.cloneFamily(c)).equals(iMetaColumnFamily)){
                result.put(Bytes.toString(CellUtil.cloneQualifier(c)), new ByteArrayByteIterator(CellUtil.cloneValue(c)));
                columns.put(Bytes.toString(CellUtil.cloneQualifier(c)), Bytes.toString(CellUtil.cloneValue(c)));
            }
        }
        return columns;
    }

    private static String decLinkData(String linkData) {
        try {
            return new String(decCipher.doFinal(Base64.getDecoder().decode(linkData)));
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt linking data");
        }
    }

    private void verifyCorrectness(Result row, String key, SortedMap <String, String> sortedColumnValues, boolean verifyColumnFamily){
        String macValue = Bytes.toString(row.getValue(iMetaColumnFamilyBytes, Bytes.toBytes("row-mac")));
        if (verifyColumnFamily){
            String hashBloom = Bytes.toString(row.getValue(iMetaColumnFamilyBytes, Bytes.toBytes(columnFamily + "-bloom-hash")));
            if (!macValue.equals(rowMac(key, hashFamily(sortedColumnValues), hashBloom)))
                throw new SecurityException("Column family was modified !");
        }else{
            String hashFamily = Bytes.toString(row.getValue(iMetaColumnFamilyBytes, Bytes.toBytes(columnFamily + "-hash")));
            BloomFilter bloomDB = new BloomFilter(row.getValue(iMetaColumnFamilyBytes, Bytes.toBytes(columnFamily + "-bloom")), BLOOM_FILTER_SIZE);
            if (!macValue.equals(rowMac(key, hashFamily, hashBloom(bloomDB))))
                throw new SecurityException("Bloom filter was modified !");

            for (String k : sortedColumnValues.keySet()){
                if (!bloomDB.contains(k + sortedColumnValues.get(k))){
                    throw new SecurityException("Column was modified !");
                }
            }
        }
    }

    private void verifyCompleteness(Result row){
        String linkDataStr = Bytes.toString(row.getValue(iMetaColumnFamilyBytes, Bytes.toBytes("link-data")));
        pool.execute(new VerificationQueriesExecutor(linkDataStr, currentTable));
    }

    @Override
    public void cleanup() throws DBException {
        try {
            pool.shutdown();
            pool.awaitTermination(1, TimeUnit.MINUTES);
            currentTable.close();
            connection.close();
        } catch (Exception e){
            throw new DBException(e);
        }
    }

    @Override
    public Status scan(String table, String startkey, int recordcount, Set<String> fields, Vector<HashMap<String, ByteIterator>> result) {
        System.out.println("------------- Performing new scan for startkey: " + startkey + "-----------");
        try(ResultScanner scanner = getScannerResult(startkey, recordcount, fields)){
            int numResults = 0;
            for (Result rr = scanner.next(); rr != null; rr = scanner.next()) {
                String key = Bytes.toString(rr.getRow());
                System.out.println("Got scan result for key: " + key);
                HashMap<String, ByteIterator> rowResult = new HashMap<String, ByteIterator>();
                SortedMap <String, String> sortedColumnValues = getColumns(rr, rowResult);
                verifyCorrectness(rr, key, sortedColumnValues, fields == null);
                verifyCompleteness(rr);
                result.add(rowResult);
                if (numResults++ >= recordcount) {
                    break;
                }
            }
        } catch (IOException e) {
            System.out.println("Error in getting/parsing scan result: " + e);
            return Status.ERROR;
        }

        return Status.OK;
    }

    private ResultScanner getScannerResult(String startkey, int recordcount, Set<String> fields) throws IOException {
        Scan s = new Scan(Bytes.toBytes(startkey));
        s.setCaching(recordcount);
        if (fields == null) {
            s.addFamily(columnFamilyBytes);
        } else {
            for (String field : fields) {
                s.addColumn(columnFamilyBytes, Bytes.toBytes(field));
            }
        }
        s.addFamily(iMetaColumnFamilyBytes);
        return currentTable.getScanner(s);
    }

    @VisibleForTesting
    void setConfiguration(final Configuration newConfig) {
        this.config = newConfig;
    }

    static class BloomFilter {
        BitSet bitSet;
        int size;

        BloomFilter(int vectorSize){
            bitSet = new BitSet(vectorSize);
            size = vectorSize;
        }

        BloomFilter(byte [] bytes, int vectorSize) {
            this.bitSet = BitSet.valueOf(bytes);
            size = vectorSize;
        }

        public void add(String s){
            bitSet.set(Math.abs(s.hashCode()) % bitSet.size());
        }

        public byte[] toBytes(){
            return bitSet.toByteArray();
        }

        public boolean contains(String value){
            return bitSet.get(Math.abs(value.hashCode()) % size);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof BloomFilter && bitSet.equals(((BloomFilter) other).bitSet);
        }

        @Override
        public String toString(){
            return bitSet.toString();
        }
    }

    private static class VerificationQueriesExecutor implements Runnable{

        private String linkData;
        private Table table;

        VerificationQueriesExecutor(String linkData, Table table){
            this.linkData = linkData;
            this.table = table;
        }

        @Override
        public void run(){
            String [] decLinkData = decLinkData(linkData).split(LINK_DATA_DELIMITER);
            for (String linkedKey : decLinkData){
                try {
                    Get g = new Get(Bytes.toBytes(linkedKey));
                    Result curResult = table.get(g);
                    if (curResult == null || curResult.isEmpty())
                        throw new SecurityException("A row is missing !");
                }catch (IOException e) {
                    throw new RuntimeException("Failed to get row ");
                }
            }
        }
    }

    @Override //not supported in our system model
    public Status update(String table, String key, HashMap<String, ByteIterator> values) {
        return Status.OK;
    }

    @Override //not supported in our system model
    public Status delete(String table, String key) {
        return Status.OK;
    }
}

