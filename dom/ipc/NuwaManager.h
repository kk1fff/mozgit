
class NuwaCallback
{
public:
  virtual void NuwaReady() = 0;
  virtual void ForkDone(ContentParent* aNewProcess) = 0;
};

class NuwaManager
{
public:
  static NuwaManager* get();
  void SetListener(NuwaCallback* aCallback);
  void NuwaReady();
  void PublishSpareProcess(ContentParent* aProcess);
  void RunNuwa();
  void KillNuwa();
};
