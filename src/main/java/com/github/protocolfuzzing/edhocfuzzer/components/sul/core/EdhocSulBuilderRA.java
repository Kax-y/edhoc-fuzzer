package com.github.protocolfuzzing.edhocfuzzer.components.sul.core;

import com.github.protocolfuzzing.edhocfuzzer.components.sul.mapper.context.EdhocExecutionContextRA;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.AbstractSul;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.utils.CleanupTasks;
import de.learnlib.ralib.words.PSymbolInstance;

public class EdhocSulBuilderRA implements SulBuilder<PSymbolInstance, PSymbolInstance, EdhocExecutionContextRA> {
    @Override
    public AbstractSul<PSymbolInstance, PSymbolInstance, EdhocExecutionContextRA> build(SulConfig sulConfig,
            CleanupTasks cleanupTasks) {
        return new EdhocSulRA(sulConfig, cleanupTasks).initialize();
    }
}
