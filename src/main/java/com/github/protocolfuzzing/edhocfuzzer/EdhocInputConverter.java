package com.github.protocolfuzzing.edhocfuzzer;

import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.symbols.inputs.*;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzerComposerRA.PSymbolInstanceConverter;
import de.learnlib.ralib.words.PSymbolInstance;
import de.learnlib.ralib.words.ParameterizedSymbol;

public class EdhocInputConverter implements PSymbolInstanceConverter<EdhocInputRA> {

    @Override
    public EdhocInputRA convert(PSymbolInstance input) {
        String name = input.getBaseSymbol().getName();
        ParameterizedSymbol base = input.getBaseSymbol();

        switch (MessageInputType.valueOf(name)) {
            case EDHOC_MESSAGE_1:
                return new EdhocMessage1InputRA(base, input.getParameterValues());

            case EDHOC_MESSAGE_2:
                return new EdhocMessage2InputRA(base, input.getParameterValues());

            case EDHOC_MESSAGE_3:
                return new EdhocMessage3InputRA(base, input.getParameterValues());

            case EDHOC_MESSAGE_3_OSCORE_APP:
                return new EdhocMessage3OscoreAppInputRA(base, input.getParameterValues());

            case EDHOC_MESSAGE_4:
                return new EdhocMessage4InputRA(base, input.getParameterValues());

            case EDHOC_ERROR_MESSAGE:
                return new EdhocErrorMessageInputRA(base, input.getParameterValues());

            case OSCORE_APP_MESSAGE:
                return new OscoreAppMessageInputRA(base, input.getParameterValues());

            case COAP_APP_MESSAGE:
                return new CoapAppMessageInputRA(base, input.getParameterValues());

            case COAP_EMPTY_MESSAGE:
                return new CoapEmptyMessageInputRA(base, input.getParameterValues());

            default:
                throw new RuntimeException("The name '" + name + "' of the " + PSymbolInstance.class.getName()
                        + "is not a member of the enum " + MessageInputType.class.getName());
        }
    }

}