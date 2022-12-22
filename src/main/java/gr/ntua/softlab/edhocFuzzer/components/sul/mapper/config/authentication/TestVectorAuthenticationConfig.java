package gr.ntua.softlab.edhocFuzzer.components.sul.mapper.config.authentication;

import com.beust.jcommander.Parameter;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Map;

public class TestVectorAuthenticationConfig {
    private TestVector testVector;

    @Parameter(names = "-testVectorJson", description = "The json file containing the test vectors")
    protected String testVectorFile = null;

    @Parameter(names = "-testVectorJsonKey", description = "The json key that maps to the desired vector. "
            + "These are the outer keys in the json file and have the format: test_vector_<number>")
    protected String testVectorJsonKey = null;

    @Parameter(names = "-testVectorPeerKeyCurve", description = "The key curve of the peer public key. "
            + "Available: Ed25519, X25519, P256")
    protected String testVectorPeerKeyCurve = null;

    public String getTestVectorFile() {
        return testVectorFile;
    }

    public String getTestVectorKey() {
        return testVectorJsonKey;
    }

    public String getTestVectorPeerKeyCurve() {
        return testVectorPeerKeyCurve;
    }

    public boolean isUsed() {
        return testVectorFile != null && testVectorJsonKey != null;
    }

    public TestVector getTestVector() {
        if (!isUsed()) {
            return null;
        }

        // return previously stored testVector
        if (testVector != null) {
            return testVector;
        }

        // store testVector after reading it from file
        testVector = jsonFile2TestVector(testVectorFile, testVectorJsonKey);
        return testVector;
    }

    private TestVector jsonFile2TestVector(String filename, String key) {
        Gson gson = new Gson();
        try(FileReader reader = new FileReader(filename)) {
            Type testVectorType = new TypeToken<Map<String, TestVector>>() {}.getType();
            Map<String, TestVector> map = gson.fromJson(reader, testVectorType);
            return map.get(key);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}