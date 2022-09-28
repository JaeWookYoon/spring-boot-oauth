package com.jwyoon.oauth.test;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.junit.Test;

public class JayyptTest {

	@Test
	public void contextLoads() {
    }

    @Test
    public void jasypt() {
        String url = "jdbc:oracle:thin:@jakedbdb_high?TNS_ADMIN=./wallet";
        

        System.out.println(jasyptEncoding(url));
        //System.out.println(jasyptEncoding(username));
        //System.out.println(jasyptEncoding(password));
    }

    public String jasyptEncoding(String value) {

        StandardPBEStringEncryptor pbeEnc = new StandardPBEStringEncryptor();
        pbeEnc.setAlgorithm("PBEWithMD5AndDES");
//        pbeEnc.setPassword(key);
        return pbeEnc.encrypt(value);
    }
}
