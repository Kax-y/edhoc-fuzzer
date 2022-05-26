package gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.mappers;

import gr.ntua.softlab.protocolStateFuzzer.components.learner.abstractSymbols.AbstractOutput;
import gr.ntua.softlab.protocolStateFuzzer.components.learner.abstractSymbols.AbstractInput;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.mapper.context.ExecutionContext;
import gr.ntua.softlab.protocolStateFuzzer.components.sul.core.protocol.ProtocolMessage;

public abstract class InputMapper {
    public void sendInput(AbstractInput input, ExecutionContext context) {
        ProtocolMessage message = input.generateProtocolMessage(context);
		input.preSendUpdate(context);
		sendMessage(message, context);
		input.postSendUpdate(context);
    }

    protected abstract void sendMessage(ProtocolMessage message, ExecutionContext context);

    public void postReceive(AbstractInput input, AbstractOutput output, ExecutionContext context) {
        input.postReceiveUpdate(output, context);
    }
}