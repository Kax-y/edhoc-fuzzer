package com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.mappers;

import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.EdhocSessionPersistent;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.EdhocUtil;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.MessageProcessorPersistent;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.EdhocProtocolMessage;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.common.CoapAppMessage;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.common.CoapEmptyMessage;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.common.EdhocErrorMessage;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.common.OscoreAppMessage;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.initiator.EdhocMessage1;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.initiator.EdhocMessage3;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.initiator.EdhocMessage3OscoreApp;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.responder.EdhocMessage2;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.responder.EdhocMessage4;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.config.EdhocMapperConfig;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.connectors.EdhocMapperConnector;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.context.EdhocExecutionContextRA;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.context.EdhocMapperState;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.symbols.inputs.MessageInputTypeRA;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.symbols.outputs.EdhocOutputCheckerRA;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputChecker;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.config.MapperConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.mappers.InputMapperRA;
import com.upokecenter.cbor.CBORObject;
import de.learnlib.ralib.data.DataValue;
import de.learnlib.ralib.words.InputSymbol;
import de.learnlib.ralib.words.PSymbolInstance;
import de.learnlib.ralib.words.ParameterizedSymbol;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.californium.core.coap.MediaTypeRegistry;

import java.util.EnumMap;

public class EdhocInputMapperRA extends InputMapperRA<PSymbolInstance, EdhocProtocolMessage, EdhocExecutionContextRA> {
    EdhocMapperConnector edhocMapperConnector;

    private static Logger LOGGER = LogManager.getLogger();
    // protected DataType T_CI = new DataType("C_I", Integer.class);

    protected EnumMap<MessageInputTypeRA, Long> timeoutMap = new EnumMap<MessageInputTypeRA, Long>(
            MessageInputTypeRA.class);

    public EdhocInputMapperRA(MapperConfig mapperConfig, EdhocOutputCheckerRA outputChecker,
            EdhocMapperConnector edhocMapperConnector) {
        super(mapperConfig, outputChecker);
        this.edhocMapperConnector = edhocMapperConnector;
    }

    @Override
    public void sendMessage(EdhocProtocolMessage message, EdhocExecutionContextRA context) {
        if (message == null) {
            throw new RuntimeException("Null message provided to EdhocInputMapperRA in sendMessage");
        }

        // enable or disable content format
        EdhocMapperConfig edhocMapperConfig = (EdhocMapperConfig) mapperConfig;
        int contentFormat = edhocMapperConfig.useContentFormat() ? message.getContentFormat()
                : MediaTypeRegistry.UNDEFINED;

        edhocMapperConnector.send(message.getPayload(), message.getPayloadType(), message.getMessageCode(),
                contentFormat);
    }

    @Override
    public void preSendUpdate(PSymbolInstance input, EdhocExecutionContextRA context) {
        String symbolName = input.getBaseSymbol().getName();
        EdhocMapperState mapperState = context.getState();

        switch (MessageInputTypeRA.valueOf(symbolName)) {
            case EDHOC_MESSAGE_1_INPUT:
                if (mapperState.getEdhocSessionPersistent().isInitiator()) {
                    // Initiator by sending message 1 starts a new key exchange session
                    // so previous session state must be cleaned unless reset is disabled
                    mapperState.getEdhocSessionPersistent().resetIfEnabled();
                }
                updateConnectionId(mapperState, input);
                break;

            case EDHOC_MESSAGE_2_INPUT:
                break;

            case EDHOC_MESSAGE_3_OSCORE_APP_INPUT:
                updateConnectionId(mapperState, input);
                // construct Message3 in order to store it in session 'message3' field,
                // derive new oscore context and make Message3 available to oscore layer
                new MessageProcessorPersistent(context.getState()).writeMessage3();
                break;

            case EDHOC_MESSAGE_3_INPUT:
            case EDHOC_MESSAGE_4_INPUT:
            case OSCORE_APP_MESSAGE_INPUT:
            case COAP_APP_MESSAGE_INPUT:
            case COAP_EMPTY_MESSAGE_INPUT:
            case EDHOC_ERROR_MESSAGE_INPUT:
                break;
        }
    }

    @Override
    public EdhocProtocolMessage generateProtocolMessage(PSymbolInstance input, EdhocExecutionContextRA context) {
        ParameterizedSymbol baseSymbol = input.getBaseSymbol();
        String symbolName = baseSymbol.getName();
        if (baseSymbol instanceof InputSymbol) {
            // We can construct this here since the switch should always dispatch to only
            // one instance.
            MessageProcessorPersistent messageProcessor = new MessageProcessorPersistent(context.getState());
            switch (MessageInputTypeRA.valueOf(symbolName)) {
                case EDHOC_MESSAGE_1_INPUT:
                    return new EdhocMessage1(messageProcessor);

                case EDHOC_MESSAGE_2_INPUT:
                    return new EdhocMessage2(messageProcessor);

                case EDHOC_MESSAGE_3_INPUT:
                    return new EdhocMessage3(messageProcessor);

                case EDHOC_MESSAGE_3_OSCORE_APP_INPUT:
                    return new EdhocMessage3OscoreApp(messageProcessor);

                case EDHOC_MESSAGE_4_INPUT:
                    return new EdhocMessage4(messageProcessor);

                case OSCORE_APP_MESSAGE_INPUT:
                    return new OscoreAppMessage(messageProcessor);

                case EDHOC_ERROR_MESSAGE_INPUT:
                    return new EdhocErrorMessage(messageProcessor);

                case COAP_APP_MESSAGE_INPUT:
                    return new CoapAppMessage(messageProcessor);

                case COAP_EMPTY_MESSAGE_INPUT:
                    return new CoapEmptyMessage(messageProcessor);
            }
        }

        throw new RuntimeException(
                "Input mapper can only map input symbols: " + baseSymbol + " is not an InputSymbol.");

    }

    @Override
    public void postReceiveUpdate(PSymbolInstance input, PSymbolInstance output,
            OutputChecker<PSymbolInstance> outputChecker, EdhocExecutionContextRA context) {
    }

    @Override
    public void postSendUpdate(PSymbolInstance input, EdhocExecutionContextRA context) {
    }

    public void updatePeerConnectionId(EdhocMapperState state, PSymbolInstance input) {
        EdhocSessionPersistent session = state.getEdhocSessionPersistent();
        LOGGER.info("Current PeerConnectionId: " + EdhocUtil.bytesToInt(session.getPeerConnectionId()));

        assert input.getParameterValues().length == 1;
        DataValue<?> dv = input.getParameterValues()[0];
        CBORObject value = CBORObject.FromObject(dv.getId());
        session.setPeerConnectionId(value.EncodeToBytes());

        LOGGER.info("PeerConnectionId after set: " +
                EdhocUtil.bytesToInt(session.getPeerConnectionId()));
    }

    public void updateConnectionId(EdhocMapperState state, PSymbolInstance input) {
        EdhocSessionPersistent session = state.getEdhocSessionPersistent();
        LOGGER.info("Current ConnectionId: {}", EdhocUtil.bytesToInt(session.getConnectionId()));

        assert input.getParameterValues().length == 1;
        DataValue<?> dv = input.getParameterValues()[0];
        CBORObject value = CBORObject.FromObject(dv.getId());
        session.setConnectionId(value.EncodeToBytes());

        LOGGER.info("ConnectionId after set: " +
                EdhocUtil.bytesToInt(session.getConnectionId()));

        EdhocSessionPersistent new_session = state.getEdhocSessionPersistent();
        byte[] new_CI = session.getConnectionId();

        state.setEdhocSessionPersistent(new_session);
        state.updateEdhocSessionsPersistent(new_CI, new_session);
    }

    public long getTimeoutForSymbol(PSymbolInstance input) {
        String baseSymbolName = input.getBaseSymbol().getName();
        MessageInputTypeRA key = MessageInputTypeRA.valueOf(baseSymbolName);
        return timeoutMap.getOrDefault(key, 0L);
    }

    public void setTimeoutForSymbol(PSymbolInstance input, long timeout) {
        String baseSymbolName = input.getBaseSymbol().getName();
        MessageInputTypeRA key = MessageInputTypeRA.valueOf(baseSymbolName);
        timeoutMap.put(key, timeout);
    }
}