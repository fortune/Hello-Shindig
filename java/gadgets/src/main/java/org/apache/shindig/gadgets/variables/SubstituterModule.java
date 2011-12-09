/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shindig.gadgets.variables;

import java.util.List;

import com.google.common.collect.Lists;
import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;

/**
 * Guice bindings for the variables package.
 *
 * @since 2.0.0
 */
public class SubstituterModule extends AbstractModule {

  @Override
  protected void configure() {
    //
    // List<Substituter> に対して実装を Bind している。
    //
    // このように Generics のときには TypeLiteral を使うようだ。
    //
    //	bind( List<Substituter>.class ).toProvider( SubstitutersProvider.class )
    //
    // のようには書けない。Java では Generics がイレイジャーだからだ。つまり、class ファイルにおいては
    // 型パラメータの情報は失われている。
    //
    bind(new TypeLiteral<List<Substituter>>(){})
        .annotatedWith(Names.named("shindig.substituters.gadget"))
        .toProvider(SubstitutersProvider.class);
  }

  public static class SubstitutersProvider implements Provider<List<Substituter>> {
    private final List<Substituter> substituters;

    @Inject
    public SubstitutersProvider(MessageSubstituter messageSubstituter,
        UserPrefSubstituter prefSubstituter,
        ModuleSubstituter moduleSubstituter,
        BidiSubstituter bidiSubstituter) {
      substituters = Lists.newArrayList();
      substituters.add(messageSubstituter);
      substituters.add(prefSubstituter);
      substituters.add(moduleSubstituter);
      substituters.add(bidiSubstituter);
    }

    public List<Substituter> get() {
      return substituters;
    }
  }
}
