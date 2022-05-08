package gr.ntua.softlab.protocolStateFuzzer.mapper;

import gr.ntua.softlab.protocolStateFuzzer.mapper.config.MapperConfig;
import gr.ntua.softlab.protocolStateFuzzer.mapper.abstractSymbols.AbstractInput;
import gr.ntua.softlab.protocolStateFuzzer.mapper.abstractSymbols.AbstractOutput;
import gr.ntua.softlab.protocolStateFuzzer.mapper.context.ExecutionContext;

/**
 * The mapper component is responsible with executing an input. 
 * Given an input symbol, the mapper should:
 * <ol>
 * 	<li> generate a corresponding packet </li>
 * 	<li> send it to the SUT </li>
 * 	<li> receive the response </li>
 * 	<li> convert it into an appropriate response </li>
 * </ol>
 * 
 */
public interface Mapper {
	AbstractOutput execute(AbstractInput input, ExecutionContext context);
	MapperConfig getMapperConfig();
	
	AbstractOutputChecker getAbstractOutputChecker();
}
