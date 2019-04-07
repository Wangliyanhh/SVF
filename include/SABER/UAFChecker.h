/*
 * UAFChecker.h
 *
 *  Created on: Dec 25, 2018
 *      Author: Liyan Wang
 */

#ifndef UAFCHECKER_H_
#define UAFCHECKER_H_

#include "SABER/LeakChecker.h"

/*!
 * Use after free checker to check consistency of uaf
 */

class UAFChecker : public LeakChecker {

public:

    /// Pass ID
    static char ID;

    /// Constructor
    UAFChecker(char id = ID): LeakChecker(ID) {
    }

    /// Destructor
    virtual ~UAFChecker() {
    }
    /// We start from here
    virtual bool runOnModule(llvm::Module& module) {
        return runOnModule(module);
    }

    /// We start from here
    virtual bool runOnModule(SVFModule module) {
        /// start analysis
        analyze(module);
        return false;
    }

    /// Get pass name
    virtual inline llvm::StringRef getPassName() const {
        return "Use after free Analysis";
    }

    /// Pass dependence
    virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const {
        /// do not intend to change the IR in this pass,
        au.setPreservesAll();
    }

    /// Report file/close bugs
    void reportBug(ProgSlice* slice);
    void reportUAF(const SVFGNode* src);
    
};


#endif /* UAFCHECK_H_ */
