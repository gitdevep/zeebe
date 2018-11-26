/*
 * Copyright © 2017 camunda services GmbH (info@camunda.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.zeebe.model.bpmn.util;

import io.zeebe.model.bpmn.instance.Activity;
import io.zeebe.model.bpmn.instance.BoundaryEvent;
import io.zeebe.model.bpmn.instance.MessageEventDefinition;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class ModelUtil {
  public static List<BoundaryEvent> getActivityBoundaryEvent(Activity activity) {
    final Collection<BoundaryEvent> boundaryEvents =
        activity.getParentElement().getChildElementsByType(BoundaryEvent.class);

    return boundaryEvents
        .stream()
        .filter(event -> event.getAttachedTo().equals(activity))
        .collect(Collectors.toList());
  }

  public static List<MessageEventDefinition> getActivityMessageBoundaryEvents(Activity activity) {
    return getActivityBoundaryEvent(activity)
        .stream()
        .flatMap(event -> event.getEventDefinitions().stream())
        .filter(definition -> definition instanceof MessageEventDefinition)
        .map(MessageEventDefinition.class::cast)
        .collect(Collectors.toList());
  }
}