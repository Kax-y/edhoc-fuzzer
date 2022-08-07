package gr.ntua.softlab.edhocFuzzer.components.sul.core.protocol;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.edhoc.*;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class EdhocSessionPersistent extends EdhocSession {
    protected boolean message2Received;

    protected boolean oscoreCtxGenerated;
    protected String oscoreUriKey;
    protected int oscoreReplayWindow;
    protected int oscoreMaxUnfragmentedSize;

    protected CBORObject[] ead1;
    protected CBORObject[] ead2;
    protected CBORObject[] ead3;
    protected CBORObject[] ead4;

    public EdhocSessionPersistent(
            boolean initiator, boolean clientInitiated, int method, byte[] connectionId,
            EdhocEndpointInfo edhocEndpointInfo, HashMapCtxDB oscoreDB) {

        super(initiator, clientInitiated, method, connectionId,
                edhocEndpointInfo.getKeyPairs(), edhocEndpointInfo.getIdCreds(), edhocEndpointInfo.getCreds(),
                edhocEndpointInfo.getSupportedCipherSuites(),
                edhocEndpointInfo.getAppProfiles().get(edhocEndpointInfo.getUri()),
                edhocEndpointInfo.getEdp(), oscoreDB);

        this.oscoreUriKey = edhocEndpointInfo.getUri();
        this.oscoreReplayWindow = edhocEndpointInfo.getOscoreReplayWindow();
        this.oscoreMaxUnfragmentedSize = edhocEndpointInfo.getOscoreMaxUnfragmentedSize();

        reset();
    }

    public void reset() {
        // own info with cipher suite 0
        setSelectedCipherSuite(Constants.EDHOC_CIPHER_SUITE_0);
        setAuthenticationCredential();
        setEphemeralKey();

        // peer dummy info
        setPeerConnectionId(new byte[]{0, 0, 0, 0});
        setPeerIdCred(CBORObject.Null);
        setPeerLongTermPublicKey(new OneKey());

        // dummy peerEphemeralPublicKey based on selectedCipherSuite 0
        OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, new byte[0]);
        setPeerEphemeralPublicKey(peerEphemeralPublicKey);

        // message1 hash
        setHashMessage1(new byte[]{1});

        // plaintext2
        setPlaintext2(new byte[]{1});

        // inner key-derivation Keys
        byte[] dummyDHSecret = SharedSecretCalculation.generateSharedSecret(getEphemeralKey(), getPeerEphemeralPublicKey());
        setPRK2e(MessageProcessor.computePRK2e(dummyDHSecret, getEdhocHashAlg(getSelectedCipherSuite())));
        setPRK3e2m(MessageProcessor.computePRK3e2m(this, getPRK2e()));
        setPRK4e3m(MessageProcessor.computePRK4e3m(this));

        // transcript hashes
        setTH2(new byte[]{1});
        setTH3(new byte[]{1});
        setTH4(new byte[]{1});

        // key after successful EDHOC execution
        setPRKout(new byte[]{1});
        setPRKexporter(new byte[]{1});

        // message3, to be used for building an EDHOC+OSCORE request
        setMessage3(new byte[]{1});

        // eads
        this.ead1 = null;
        this.ead2 = null;
        this.ead3 = null;
        this.ead4 = null;

        // setup dummy oscore context
        // and reset flag to false
        oscoreCtxGenerated = false;
        setupOscoreContext();
        oscoreCtxGenerated = false;

        // reset other flags
        message2Received = false;
    }

    public void setupOscoreContext() {
        if (!getApplicationProfile().getUsedForOSCORE() || oscoreCtxGenerated) {
            return;
        }

        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
        byte[] masterSecret = getMasterSecretOSCORE(this);
        byte[] masterSalt = getMasterSaltOSCORE(this);

        /* Set up the OSCORE Security Context */

        // The Sender ID of this peer is the EDHOC connection identifier of the other peer
        byte[] senderId = getPeerConnectionId();
        // The Recipient ID of this peer is the EDHOC connection identifier of this peer
        byte[] recipientId = getConnectionId();

        int selectedCipherSuite = getSelectedCipherSuite();
        AlgorithmID alg = getAppAEAD(selectedCipherSuite);
        AlgorithmID hkdf = getAppHkdf(selectedCipherSuite);

        OSCoreCtx ctx;
        if (Arrays.equals(senderId, recipientId)) {
            throw new RuntimeException("Error: the Sender ID coincides with the Recipient ID");
        }

        try {
            ctx = new OSCoreCtx(masterSecret, true, alg, senderId, recipientId, hkdf,
                    oscoreReplayWindow, masterSalt, null, oscoreMaxUnfragmentedSize);
        } catch (OSException e) {
            throw new RuntimeException("Error when deriving the OSCORE Security Context: " + e.getMessage());
        }

        try {
            getOscoreDb().addContext(oscoreUriKey, ctx);
        } catch (OSException e) {
            throw new RuntimeException("Error when adding the OSCORE Security Context to the context database: "
                    + e.getMessage());
        }

        oscoreCtxGenerated = true;
    }

    public boolean isMessage2Received() {
        return message2Received;
    }

    public void setMessage2Received() {
        message2Received = true;
    }

    @Override
    public void deleteTemporaryMaterial() {
        // do not delete anything
    }

    @Override
    public void cleanMessage1() {
        // do not clean anything
    }

    @Override
    public void cleanMessage3() {
        // do not clean anything
    }

    @Override
    public byte[] edhocExporter(int label, CBORObject context, int len) throws InvalidKeyException, NoSuchAlgorithmException {
        if (label < 0 || context.getType() != CBORType.ByteString || len < 0)
            return null;
        // do not check for session currentStep
        return edhocKDF(getPRKexporter(), label, context, len);
    }

    public CBORObject[] getEad1() {
        return ead1;
    }

    public void setEad1(CBORObject[] ead1) {
        this.ead1 = ead1;
    }

    public CBORObject[] getEad2() {
        return ead2;
    }

    public void setEad2(CBORObject[] ead2) {
        this.ead2 = ead2;
    }

    public CBORObject[] getEad3() {
        return ead3;
    }

    public void setEad3(CBORObject[] ead3) {
        this.ead3 = ead3;
    }

    public CBORObject[] getEad4() {
        return ead4;
    }

    public void setEad4(CBORObject[] ead4) {
        this.ead4 = ead4;
    }
}
