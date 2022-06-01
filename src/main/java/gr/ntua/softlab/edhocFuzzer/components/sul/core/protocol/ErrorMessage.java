package gr.ntua.softlab.edhocFuzzer.components.sul.core.protocol;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.edhoc.EdhocSession;
import org.eclipse.californium.edhoc.MessageProcessor;

public class ErrorMessage extends EdhocProtocolMessage {

    ErrorMessage(int errorCode, int replyTo, boolean isErrorReq, CBORObject cX, String errMsg, CBORObject suitesR) {
        cborSequence = MessageProcessor.writeErrorMessage(errorCode, replyTo, isErrorReq, cX, errMsg, suitesR);
    }
}
