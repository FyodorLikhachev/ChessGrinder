package com.chessgrinder.chessgrinder.chessengine.pairings;

import java.util.*;

import com.chessgrinder.chessgrinder.dto.*;

public interface PairingStrategy {

    List<MatchDto> makePairings(
            List<ParticipantDto> participantIds,
            /**
             * List per round.
             */
            List<List<MatchDto>> matchHistory,
            Integer roundsNumber
    );
}


