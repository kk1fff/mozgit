/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "PreallocatedCreatorNuwa.cpp"

void
PreallocatedCreatorNuwa::Init()
{
  CreateNuwaProcess();
}

void
PreallocatedCreatorNuwa::CreateNuwaProcess()
{
  MOZ_ASSERT(!mNuwaProcess, "Nuwa is not ready when created");
  mNuwaProcess = ContentParent::RunNuwaProcess();
}

// Implement NuwaCallback
void
PreallocatedCreatorNuwa::NuwaReady()
{
  MOZ_ASSERT(!IsReady(), "Nuwa should become ready before creator gets ready.");

  // Now we're ready.
  mIsReady = true;

  if (Preferences::GetBool("dom.ipc.preallocatedProcessManager.testMode")) {
    AutoJSContext cx;
    nsCOMPtr<nsIMessageBroadcaster> ppmm =
      do_GetService("@mozilla.org/parentprocessmessagemanager;1");
    mozilla::unused << ppmm->BroadcastAsyncMessage(
      NS_LITERAL_STRING("TEST-ONLY:nuwa-ready"),
      JS::NullHandleValue, JS::NullHandleValue, cx, 1);
  }

  mCallback->InitializeDone();
}

void
PreallocatedCreatorNuwa::ForkDone(ContentParent* aNewProcess)
{
  MOZ_ASSERT(IsReady(), "Getting a new process only when Nuwa is ready.");
  mProcess = aNewProcess;
  mCallback->ProcessReady();
}

// Implement PreallocatedProcessCreator
void
PreallocatedCreatorNuwa::CreateProcess()
{
  MOZ_ASSERT(!mProcess, "There's already a process created");
  NuwaFork();
}

already_AddRefed<ContentParent>
PreallocatedCreatorNuwa::GetProcess()
{
  return mProcess.forget();
}

bool
PreallocatedCreatorNuwa::IsReady()
{
  return mIsReady;
}
