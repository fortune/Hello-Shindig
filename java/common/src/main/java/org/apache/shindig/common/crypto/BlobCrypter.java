/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shindig.common.crypto;

import java.util.Map;

/**
 * Utility interface for managing signed, encrypted, and time stamped blobs.
 * Blobs are made up of name/value pairs.  Time stamps are automatically
 * included and checked.
 *
 * Thread safe.
 */
public interface BlobCrypter {

  /**
   * Time stamps, encrypts, and signs a blob.
   * 
   * in に格納されている name/value ペアから暗号化し、その上で BASE64 文字列を作り出す。
   * タイムスタンプは自動的に付与する。
   *
   * @param in name/value pairs to encrypt
   * @return a base64 encoded blob
   *
   * @throws BlobCrypterException when crypto errors occur
   */
  String wrap(Map<String, String> in) throws BlobCrypterException;

  /**
   * Unwraps a blob.
   * 
   * 暗号文字列をデコードし、name/value ペアを生成して返す。もし、暗号文中に
   * 付与されているタイムスタンプと maxAgeSec を比較して、文字列が古すぎる場合は例外をスローする。
   *
   * @param in blob
   * @param maxAgeSec maximum age for the blob
   * @return the name/value pairs, including the origin timestamp.
   *
   * @throws BlobExpiredException if the blob is too old to be accepted.
   * @throws BlobCrypterException if the blob can't be decoded.
   */
  Map<String, String> unwrap(String in, int maxAgeSec)
      throws BlobCrypterException;
}
