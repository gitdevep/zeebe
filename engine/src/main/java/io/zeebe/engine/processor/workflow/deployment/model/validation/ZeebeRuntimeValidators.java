/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Zeebe Community License 1.0. You may not use this file
 * except in compliance with the Zeebe Community License 1.0.
 */
package io.zeebe.engine.processor.workflow.deployment.model.validation;

import io.zeebe.el.ExpressionLanguage;
import io.zeebe.model.bpmn.instance.ConditionExpression;
import io.zeebe.model.bpmn.instance.zeebe.ZeebeCalledElement;
import io.zeebe.model.bpmn.instance.zeebe.ZeebeInput;
import io.zeebe.model.bpmn.instance.zeebe.ZeebeLoopCharacteristics;
import io.zeebe.model.bpmn.instance.zeebe.ZeebeOutput;
import io.zeebe.model.bpmn.instance.zeebe.ZeebeSubscription;
import java.util.Collection;
import java.util.List;
import org.camunda.bpm.model.xml.validation.ModelElementValidator;

public final class ZeebeRuntimeValidators {

  public static final Collection<ModelElementValidator<?>> getValidators(
      final ExpressionLanguage expressionLanguage) {
    return List.of(
        ZeebeExpressionValidator.verifyThat(ZeebeInput.class)
            .hasValidNonStaticExpression(ZeebeInput::getSource)
            .hasValidPath(ZeebeInput::getTarget)
            .build(expressionLanguage),
        ZeebeExpressionValidator.verifyThat(ZeebeOutput.class)
            .hasValidNonStaticExpression(ZeebeOutput::getSource)
            .hasValidPath(ZeebeOutput::getTarget)
            .build(expressionLanguage),
        ZeebeJsonPathValidator.verifyThat(ZeebeSubscription.class)
            .hasValidPathExpression(ZeebeSubscription::getCorrelationKey)
            .build(),
        ZeebeJsonPathValidator.verifyThat(ZeebeLoopCharacteristics.class)
            .hasValidPathExpression(ZeebeLoopCharacteristics::getInputCollection)
            .hasValidPathExpression(ZeebeLoopCharacteristics::getOutputElement)
            .build(),
        ZeebeExpressionValidator.verifyThat(ZeebeCalledElement.class)
            .hasValidExpression(ZeebeCalledElement::getProcessId)
            .build(expressionLanguage),
        ZeebeExpressionValidator.verifyThat(ConditionExpression.class)
            .hasValidExpression(ConditionExpression::getTextContent)
            .build(expressionLanguage));
  }
}
