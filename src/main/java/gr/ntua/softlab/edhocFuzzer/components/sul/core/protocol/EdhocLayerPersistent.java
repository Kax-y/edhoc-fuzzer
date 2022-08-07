package gr.ntua.softlab.edhocFuzzer.components.sul.core.protocol;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.edhoc.EdhocEndpointInfo;
import org.eclipse.californium.edhoc.EdhocSession;
import org.eclipse.californium.edhoc.MessageProcessor;
import org.eclipse.californium.edhoc.Util;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/** Adapted from {@link org.eclipse.californium.edhoc.EdhocLayer} */
public class EdhocLayerPersistent extends AbstractLayer {
    private static final Logger LOGGER = LoggerFactory.getLogger(EdhocLayerPersistent.class);


    // The OSCORE context database
    OSCoreCtxDB ctxDb;


     // Map of existing EDHOC sessions
    HashMap<CBORObject, EdhocSession> edhocSessions;

    // MessageProcessor for reading message 3
    MessageProcessorPersistent messageProcessorPersistent;

    public EdhocLayerPersistent(EdhocEndpointInfo edhocEndpointInfo,
                                MessageProcessorPersistent messageProcessorPersistent) {
        this.ctxDb = edhocEndpointInfo.getOscoreDb();
        this.edhocSessions = edhocEndpointInfo.getEdhocSessions();
        this.messageProcessorPersistent = messageProcessorPersistent;
        LOGGER.debug("Initializing EDHOC layer persistent");
    }

    @Override
    public void sendRequest(final Exchange exchange, final Request request) {

        LOGGER.debug("Sending request through EDHOC layer");

        if (request.getOptions().hasEdhoc() && request.getOptions().hasOscore()) {
            LOGGER.debug("Combined EDHOC+OSCORE request");

            // Retrieve the Security Context used to protect the request
            OSCoreCtx ctx = getContextForOutgoing(exchange);

            // The connection identifier of this peer is its Recipient ID
            byte[] recipientId = ctx.getRecipientId();
            CBORObject connectionIdentifierInitiatorCbor = CBORObject.FromObject(recipientId);

            // Retrieve the EDHOC session associated to C_R and storing EDHOC message_3
            EdhocSession session = this.edhocSessions.get(connectionIdentifierInitiatorCbor);

            // Consistency checks
            if (session == null) {
                LOGGER.debug("ERROR: Unable to retrieve the EDHOC session");
                return;
            }

            byte[] connectionIdentifierInitiator = session.getConnectionId();
            if (!Arrays.equals(recipientId, connectionIdentifierInitiator)) {
                LOGGER.debug("ERROR: Retrieved inconsistent EDHOC session");
                return;
            }

            // Extract CIPHERTEXT_3 as the second element of EDHOC message_3
            byte[] message3 = session.getMessage3();
            CBORObject[] message3Elements = CBORObject.DecodeSequenceFromBytes(message3);
            byte[] ciphertext3 = message3Elements[1].GetByteString();

            // Original OSCORE payload from the request
            byte[] oldOscorePayload = request.getPayload();

            LOGGER.debug(EdhocUtil.byteArrayToString("Message 3", message3));
            LOGGER.debug(EdhocUtil.byteArrayToString("CIPHERTEXT_3", ciphertext3));
            LOGGER.debug(EdhocUtil.byteArrayToString("Old OSCORE payload", oldOscorePayload));

            // Build the new OSCORE payload, as a CBOR sequence of two elements
            // 1. A CBOR byte string, i.e. EDHOC CIPHERTEXT_3 as is
            // 2. A CBOR byte string, with value the original OSCORE payload
            byte[] ciphertext3Cbor = CBORObject.FromObject(ciphertext3).EncodeToBytes();
            byte[] oldOscorePayloadCbor = CBORObject.FromObject(oldOscorePayload).EncodeToBytes();

            int newOscorePayloadLength = ciphertext3Cbor.length + oldOscorePayloadCbor.length;

            // Abort if the payload of the EDHOC+OSCORE request exceeds MAX_UNFRAGMENTED_SIZE
            int maxUnfragmentedSize = ctx.getMaxUnfragmentedSize();
            if (newOscorePayloadLength > maxUnfragmentedSize) {
                throw new IllegalStateException("The payload of the EDHOC+OSCORE request is exceeding MAX_UNFRAGMENTED_SIZE");
            }

            byte[] newOscorePayload = new byte[newOscorePayloadLength];
            System.arraycopy(ciphertext3Cbor, 0, newOscorePayload, 0, ciphertext3Cbor.length);
            System.arraycopy(oldOscorePayloadCbor, 0, newOscorePayload, ciphertext3Cbor.length, oldOscorePayloadCbor.length);

            LOGGER.debug(EdhocUtil.byteArrayToString("New OSCORE payload", newOscorePayload));

            // Set the new OSCORE payload as payload of the EDHOC+OSCORE request
            request.setPayload(newOscorePayload);
        }

        super.sendRequest(exchange, request);
    }

    @Override
    public void sendResponse(Exchange exchange, Response response) {
        LOGGER.debug("Sending response through EDHOC layer");
        super.sendResponse(exchange, response);
    }

    @Override
    public void receiveRequest(Exchange exchange, Request request) {

        LOGGER.debug("Receiving request through EDHOC layer");

        if (request.getOptions().hasEdhoc()) {

            if (!request.getOptions().hasOscore()) {
                LOGGER.debug("ERROR: Received a request with the EDHOC option but without the OSCORE option");
                return;
            }

            LOGGER.debug("Combined EDHOC+OSCORE request");

            // Retrieve the received payload combining EDHOC CIPHERTEXT_3 and the real OSCORE payload
            byte[] oldPayload = request.getPayload();

            // CBOR objects included in the received CBOR sequence
            CBORObject[] receivedOjectList = CBORObject.DecodeSequenceFromBytes(oldPayload);

            if (receivedOjectList == null || receivedOjectList.length != 2) {
                LOGGER.debug("ERROR: Received CBOR Object List is null or has invalid length");
                return;
            }

            if (receivedOjectList[0].getType() != CBORType.ByteString ||
                    receivedOjectList[1].getType() != CBORType.ByteString) {
                LOGGER.debug("ERROR: Received CBOR Objects have invalid type");
                return;
            }

            // Prepare the actual OSCORE request, by replacing the payload
            byte[] newPayload = receivedOjectList[1].GetByteString();
            request.setPayload(newPayload);

            LOGGER.debug(EdhocUtil.byteArrayToString("Received payload", oldPayload));
            LOGGER.debug(EdhocUtil.byteArrayToString("OSCORE request payload", newPayload));

            // Rebuild the full EDHOC message_3

            List<CBORObject> edhocObjectList = new ArrayList<>();

            // Add C_R, by encoding the 'kid' from the OSCORE option
            byte[] kid = getKid(request.getOptions().getOscore());
            CBORObject cR = MessageProcessor.encodeIdentifier(kid);
            edhocObjectList.add(cR);

            // Add CIPHERTEXT_3, i.e. the CBOR string as is from the received CBOR sequence
            edhocObjectList.add(receivedOjectList[0]);

            // Assemble the full EDHOC message_3
            byte[] edhocMessage3 = Util.buildCBORSequence(edhocObjectList);

            LOGGER.debug(EdhocUtil.byteArrayToString("Rebuilt EDHOC message_3", edhocMessage3));

            CBORObject kidCbor = CBORObject.FromObject(kid);
            EdhocSession mySession = edhocSessions.get(kidCbor);

            // Consistency checks
            if (mySession == null) {
                LOGGER.debug("ERROR: Unable to retrieve the EDHOC session");
                return;
            }

            // Process EDHOC message_3
            boolean ok = messageProcessorPersistent.readMessage3(edhocMessage3, true, null);

            // TODO complete according to need
        }

        super.receiveRequest(exchange, request);
    }

    @Override
    public void receiveResponse(Exchange exchange, Response response) {
        LOGGER.debug("Receiving response through EDHOC layer");
        super.receiveResponse(exchange, response);
    }

    @Override
    public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
        super.sendEmptyMessage(exchange, message);
    }

    @Override
    public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
        super.receiveEmptyMessage(exchange, message);
    }

    /**
     * Returns the OSCORE Context that was used to protect this outgoing
     * exchange (outgoing request or response).
     */
    protected OSCoreCtx getContextForOutgoing(Exchange e) {

        String uri = e.getRequest().getURI();
        if (uri == null) {
            return null;
        }

        try {
            return ctxDb.getContext(uri);
        } catch (OSException exception) {
            LOGGER.debug("ERROR: Retrieving the OSCORE Security Context " + exception.getMessage());
            return null;
        }
    }

    /**
     * Retrieve KID value from an OSCORE option.
     */
    protected byte[] getKid(byte[] oscoreOption) {
        if (oscoreOption.length == 0) {
            return null;
        }

        // Parse the flag byte
        byte flagByte = oscoreOption[0];
        int n = flagByte & 0x07;
        int k = flagByte & 0x08;
        int h = flagByte & 0x10;

        byte[] kid = null;
        int index = 1;

        // Partial IV
        index += n;

        // KID Context
        if (h != 0) {
            int s = oscoreOption[index];
            index += s + 1;
        }

        // KID
        if (k != 0) {
            kid = Arrays.copyOfRange(oscoreOption, index, oscoreOption.length);
        }

        return kid;
    }
}
