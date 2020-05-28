#ifndef PCRSELECTION_H
#define PCRSELECTION_H
#include "ibmtss/TPM_Types.h"
#include <cstdarg>

class PCRSelector {
public:
    PCRSelector(TPMI_ALG_HASH hashAlg) {
        this->hashAlg = hashAlg;
    }

    void use_pcrs(uint8_t num, ...) {
        selection = TPML_PCR_SELECTION();
        selection.count = 1; // We only have one bank (could be multiple ofc)
        selection.pcrSelections[0].hash = hashAlg;
        selection.pcrSelections[0].sizeofSelect = 3;    /* hard code 24 PCRs */

        va_list valist;
        va_start(valist, num);

        for (int i = 0; i < num; i++) {
            int bit = va_arg(valist, int);
            int bitToSet = ((bit - 1) % 8);
            int byteToSet = (int)((bit-1)/8);
            selection.pcrSelections[0].pcrSelect[byteToSet] |= 1 << bitToSet;
        }
    }

    // Set the PCRs with a maski
    void set_pcrs(uint32_t mask) {
        selection = TPML_PCR_SELECTION();
        selection.count = 1; // We only have one bank (could be multiple ofc)
        selection.pcrSelections[0].hash = hashAlg;
        selection.pcrSelections[0].sizeofSelect = 3;    /* hard code 24 PCRs */

        selection.pcrSelections[0].pcrSelect[0] = static_cast<BYTE>((mask >> 0) & 0xff);
        selection.pcrSelections[0].pcrSelect[1] = static_cast<BYTE>((mask >> 8) & 0xff);
        selection.pcrSelections[0].pcrSelect[2] = static_cast<BYTE>((mask >> 16) & 0xff);
    }

    // Returns the selection
    TPML_PCR_SELECTION getSelection() {
        return this->selection;
    }

private:
    TPML_PCR_SELECTION selection{};
    TPMI_ALG_HASH hashAlg;
};

#endif // PCRSELECTION_H
