//===- DLL.h ----------------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLD_COFF_DLL_H
#define LLD_COFF_DLL_H

#include "Chunks.h"
#include "Symbols.h"

namespace lld::coff {

// Windows-specific.
// IdataContents creates all chunks for the DLL import table.
// You are supposed to call add() to add symbols and then
// call create() to populate the chunk vectors.
class IdataContents {
public:
  void add(DefinedImportData *sym) { imports.push_back(sym); }
  bool empty() { return imports.empty(); }

  void create(COFFLinkerContext &ctx);

  std::vector<DefinedImportData *> imports;
  std::vector<Chunk *> dirs;
  std::vector<Chunk *> lookups;
  std::vector<Chunk *> addresses;
  std::vector<Chunk *> hints;
  std::vector<Chunk *> dllNames;
  std::vector<StringRef> dllNamesStrings;
};

// Windows-specific.
// .fixPath contents as version and dllname_max_size
class FixPathContents {
public:
  void addIData(StringRef dll) {
    iData.push_back(make<StringChunk>(dll));
  }
  void addDelayIData(StringRef dll) {
    delayIData.push_back(make<StringChunk>(dll));
  }
  uint32_t getVersion() {
    return version;
  }
  uint32_t getDllnameMaxSize() {
      return dllname_max_size;
  }
  // FIXME make private
  std::vector<Chunk *> iData;
  std::vector<Chunk *> delayIData;
  // dllname_max_size - a guaranteed size for a dll filename,
  // i.e. "KERNEL32.dll" or "C:\nix\store\long-dir-name\foo.dll"
private:
  uint32_t version = 2;
  uint32_t dllname_max_size = 301;
};

// Windows-specific.
// DelayLoadContents creates all chunks for the delay-load DLL import table.
class DelayLoadContents {
public:
  DelayLoadContents(COFFLinkerContext &ctx) : ctx(ctx) {}
  void add(DefinedImportData *sym) { imports.push_back(sym); }
  bool empty() { return imports.empty(); }
  void create(Defined *helper);
  std::vector<Chunk *> getChunks();
  std::vector<Chunk *> getDataChunks();
  ArrayRef<Chunk *> getCodeChunks() { return thunks; }
  ArrayRef<Chunk *> getCodePData() { return pdata; }
  ArrayRef<Chunk *> getCodeUnwindInfo() { return unwindinfo; }

  uint64_t getDirRVA() { return dirs[0]->getRVA(); }
  uint64_t getDirSize();
  std::vector<StringRef> dllNamesStrings;

private:
  Chunk *newThunkChunk(DefinedImportData *s, Chunk *tailMerge);
  Chunk *newTailMergeChunk(Chunk *dir);
  Chunk *newTailMergePDataChunk(Chunk *tm, Chunk *unwind);
  Chunk *newTailMergeUnwindInfoChunk();

  Defined *helper;
  std::vector<DefinedImportData *> imports;
  std::vector<Chunk *> dirs;
  std::vector<Chunk *> moduleHandles;
  std::vector<Chunk *> addresses;
  std::vector<Chunk *> names;
  std::vector<Chunk *> hintNames;
  std::vector<Chunk *> thunks;
  std::vector<Chunk *> pdata;
  std::vector<Chunk *> unwindinfo;
  std::vector<Chunk *> dllNames;

  COFFLinkerContext &ctx;
};

// Windows-specific.
// EdataContents creates all chunks for the DLL export table.
class EdataContents {
public:
  EdataContents(COFFLinkerContext &ctx);
  std::vector<Chunk *> chunks;

  uint64_t getRVA() { return chunks[0]->getRVA(); }
  uint64_t getSize() {
    return chunks.back()->getRVA() + chunks.back()->getSize() - getRVA();
  }

  COFFLinkerContext &ctx;
};

// A chunk for linker-created strings with a preallocated/fixed output size
// so that DLL names in the PE header can be patched similar to rpath on Linux.
class StringChunkReservedSize : public NonSectionChunk {
public:
  StringChunkReservedSize(COFFLinkerContext &ctx, StringRef s) : str(s), ctx(ctx) {}
  void writeTo(uint8_t *buf) const override;
  size_t getSize() const override;

private:
  StringRef str;
  COFFLinkerContext &ctx;
};

} // namespace lld::coff

#endif
