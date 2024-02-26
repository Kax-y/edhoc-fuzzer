package com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.symbols.inputs;

import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.MessageProcessorPersistent;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.EdhocProtocolMessage;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.common.CoapAppMessage;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.context.EdhocExecutionContextRA;
import de.learnlib.ralib.data.DataValue;
import de.learnlib.ralib.words.ParameterizedSymbol;

public class CoapAppMessageInputRA extends EdhocInputRA {

    CoapAppMessageInputRA(ParameterizedSymbol baseSymbol, @SuppressWarnings("rawtypes") DataValue[] parameterValues) {
        super(baseSymbol, parameterValues);
    }

    @Override
    public EdhocProtocolMessage generateProtocolMessage(EdhocExecutionContextRA context) {
        return new CoapAppMessage(new MessageProcessorPersistent(context.getState()));
    }

    @Override
    public Enum<MessageInputType> getInputType() {
        return MessageInputType.COAP_APP_MESSAGE;
    }
}
