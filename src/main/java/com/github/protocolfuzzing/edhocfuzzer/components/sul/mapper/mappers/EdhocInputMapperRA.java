package com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.mappers;

import com.github.protocolfuzzing.edhocfuzzer.components.sul.core.protocol.messages.EdhocProtocolMessage;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.config.EdhocMapperConfig;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.connectors.EdhocMapperConnector;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.context.EdhocExecutionContextRA;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.symbols.inputs.EdhocInputRA;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.symbols.outputs.EdhocOutputCheckerRA;
import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.symbols.outputs.EdhocOutputRA;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.config.MapperConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.mappers.InputMapper;
import org.eclipse.californium.core.coap.MediaTypeRegistry;

public class EdhocInputMapperRA extends InputMapper<EdhocInputRA, EdhocOutputRA, EdhocProtocolMessage, EdhocExecutionContextRA> {
    EdhocMapperConnector edhocMapperConnector;

    public EdhocInputMapperRA(MapperConfig mapperConfig, EdhocOutputCheckerRA outputChecker, EdhocMapperConnector edhocMapperConnector) {
        super(mapperConfig, outputChecker);
        this.edhocMapperConnector = edhocMapperConnector;
    }

    @Override
    protected void sendMessage(EdhocProtocolMessage message, EdhocExecutionContextRA context) {
        if (message == null) {
            throw new RuntimeException("Null message provided to EdhocInputMapper in sendMessage");
        }

        // enable or disable content format
        EdhocMapperConfig edhocMapperConfig = (EdhocMapperConfig) mapperConfig;
        int contentFormat = edhocMapperConfig.useContentFormat() ? message.getContentFormat() : MediaTypeRegistry.UNDEFINED;

        edhocMapperConnector.send(message.getPayload(), message.getPayloadType(), message.getMessageCode(), contentFormat);
    }
}