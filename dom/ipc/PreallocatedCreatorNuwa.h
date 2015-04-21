/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_PreallocatedProcessCreatorNuwa_h
#define mozilla_PreallocatedProcessCreatorNuwa_h

#include "PreallocatedProcessManager.h"

class PreallocatedCreatorNuwa: public PreallocatedProcessCreator
                             , public NuwaCallback
{
public:
  void Init();

  virtual void NuwaReady();
  virtual void ForkDone(ContentParent* aNewProcess);
  
  virtual ContentParent* CreateProcess();
  virtual bool IsReady();
private:
  void CreateNuwaProcess();
};

#endif // mozilla_PreallocatedProcessCreateorNuwa_h
