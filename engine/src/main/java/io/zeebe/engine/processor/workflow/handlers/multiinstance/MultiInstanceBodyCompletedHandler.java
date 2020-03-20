/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Zeebe Community License 1.0. You may not use this file
 * except in compliance with the Zeebe Community License 1.0.
 */
package io.zeebe.engine.processor.workflow.handlers.multiinstance;

import static io.zeebe.util.buffer.BufferUtil.cloneBuffer;

import io.zeebe.engine.processor.workflow.BpmnStepContext;
import io.zeebe.engine.processor.workflow.BpmnStepHandler;
import io.zeebe.engine.processor.workflow.ExpressionProcessor;
import io.zeebe.engine.processor.workflow.deployment.model.BpmnStep;
import io.zeebe.engine.processor.workflow.deployment.model.element.ExecutableMultiInstanceBody;
import io.zeebe.msgpack.query.MsgPackQueryProcessor;
import io.zeebe.msgpack.spec.MsgPackReader;
import io.zeebe.msgpack.spec.MsgPackWriter;
import java.util.function.Function;
import org.agrona.DirectBuffer;
import org.agrona.ExpandableArrayBuffer;
import org.agrona.concurrent.UnsafeBuffer;

public final class MultiInstanceBodyCompletedHandler extends AbstractMultiInstanceBodyHandler {

  private final BpmnStepHandler multiInstanceBodyHandler;

  private final MsgPackReader variableReader = new MsgPackReader();
  private final MsgPackWriter variableWriter = new MsgPackWriter();
  private final MsgPackQueryProcessor queryProcessor = new MsgPackQueryProcessor();

  private final ExpandableArrayBuffer variableBuffer = new ExpandableArrayBuffer();
  private final DirectBuffer resultBuffer = new UnsafeBuffer(0, 0);

  public MultiInstanceBodyCompletedHandler(
      final Function<BpmnStep, BpmnStepHandler> innerHandlerLookup,
      final ExpressionProcessor expressionProcessor) {
    super(null, innerHandlerLookup, expressionProcessor);
    this.multiInstanceBodyHandler = innerHandlerLookup.apply(BpmnStep.FLOWOUT_ELEMENT_COMPLETED);
  }

  @Override
  protected void handleInnerActivity(final BpmnStepContext<ExecutableMultiInstanceBody> context) {
    final var loopCharacteristics = context.getElement().getLoopCharacteristics();

    if (loopCharacteristics.isSequential()) {

      final var array =
          readInputCollectionVariable(context).orElseThrow(IllegalStateException::new);

      final var loopCounter = context.getFlowScopeInstance().getMultiInstanceLoopCounter();

      if (loopCounter < array.size()) {

        final var item = array.get(loopCounter);
        createInnerInstance(context, context.getFlowScopeInstance().getKey(), item);
      }
    }

    loopCharacteristics
        .getOutputCollection()
        .ifPresent(variableName -> updateOutputCollection(context, variableName));

    // completing the multi-instance body if there are no more tokens
    super.handleInnerActivity(context);
  }

  @Override
  protected boolean handleMultiInstanceBody(
      final BpmnStepContext<ExecutableMultiInstanceBody> context) {
    multiInstanceBodyHandler.handle(context);
    return true;
  }

  protected void updateOutputCollection(
      final BpmnStepContext<ExecutableMultiInstanceBody> context, final DirectBuffer variableName) {

    final var variablesState = context.getElementInstanceState().getVariablesState();
    final var bodyInstanceKey = context.getFlowScopeInstance().getKey();
    final var workflowKey = context.getValue().getWorkflowKey();
    final var loopCounter = context.getElementInstance().getMultiInstanceLoopCounter();

    // the result needs to be cloned because readOutputElementVariable(Context) uses the same buffer
    final var currentCollection =
        cloneBuffer(variablesState.getVariableLocal(bodyInstanceKey, variableName));

    final DirectBuffer elementVariable = readOutputElementVariable(context);
    if (elementVariable != null) {
      final var updatedCollection = insertAt(currentCollection, loopCounter, elementVariable);
      variablesState.setVariableLocal(
          bodyInstanceKey, workflowKey, variableName, updatedCollection);
    }
  }

  private DirectBuffer insertAt(
      final DirectBuffer array, final int index, final DirectBuffer element) {

    variableReader.wrap(array, 0, array.capacity());
    variableReader.readArrayHeader();
    variableReader.skipValues(index - 1);

    final var offsetBefore = variableReader.getOffset();
    variableReader.skipValue();
    final var offsetAfter = variableReader.getOffset();

    variableWriter.wrap(variableBuffer, 0);
    variableWriter.writeRaw(array, 0, offsetBefore);
    variableWriter.writeRaw(element);
    variableWriter.writeRaw(array, offsetAfter, array.capacity() - offsetAfter);

    final var length = variableWriter.getOffset();

    resultBuffer.wrap(variableBuffer, 0, length);
    return resultBuffer;
  }
}
