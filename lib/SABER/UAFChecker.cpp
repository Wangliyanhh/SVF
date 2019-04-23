/*
 * UAFChecker.cpp
 *
 *  Created on: Dec 25, 2018
 *      Author: Liyan Wang
 */

#include "SABER/UAFChecker.h"
#include "Util/AnalysisUtil.h"
#include "MSSA/SVFGStat.h"
#include "Util/GraphUtil.h"
#include <llvm/Support/CommandLine.h>

using namespace llvm;
using namespace analysisUtil;

char UAFChecker::ID = 0;

static RegisterPass<UAFChecker> UAFCHECKER("uaf-checker",
        "Use After Free Checker");

void UAFChecker::reportUAF(const SVFGNode* src) {
    CallSite cs = getSrcCSID(src);
    errs() << bugMsg1("\t UseAfterFree :") <<  " memory dellocation at : ("
           << getSourceLoc(cs.getInstruction()) << ")\n";    
}
//add
void UAFChecker::reportBug(ProgSlice* slice) {
    if(isUseAfterFree(slice) == false){
        const SVFGNode* src = slice->getSource();
        CallSite cs2 = dyn_cast<ActualParmSVFGNode>(slice->getSNode())->getCallSite();    
        const Instruction *uinst= dyn_cast<StmtSVFGNode>(slice->getUNode())->getInst();
        CallSite cs = getSrcCSID(src);
        errs() << bugMsg2("\t Use Afree Free :") <<  " memory allocation at : ("
               << getSourceLoc(cs.getInstruction()) << ")\n";
        errs() << "\t\t free location: (" << getSourceLoc(cs2.getInstruction()) << ")\n";
        errs() << "\t\t use location: (" << getSourceLoc(dyn_cast<Value>(uinst)) << ")\n";
        errs() << "\t\t Use after free path: \n" << slice->evalFinalCond() << "\n";
        slice->annotatePaths();
    }
}