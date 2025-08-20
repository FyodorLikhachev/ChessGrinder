import {Link, useNavigate, useParams} from "react-router-dom";
import React, {useMemo} from "react";
import ResultsTable from "pages/TournamentPage/ResultsTable";
import {useQuery} from "@tanstack/react-query";
import tournamentPageRepository from "lib/api/repository/TournamentPageRepository";
import {MatchDto, MatchResult, ParticipantDto, TournamentPageData} from "lib/api/dto/TournamentPageData";
import RoundTab from "pages/TournamentPage/RoundTab";
import {Conditional, usePermissionGranted} from "components/Conditional";
import participantRepository from "lib/api/repository/ParticipantRepository";
import {AiOutlineDelete, AiOutlineEdit, AiOutlineHome, AiOutlinePlus, AiOutlineCopy} from "react-icons/ai";
import {useLoc} from "strings/loc";
import tournamentRepository from "lib/api/repository/TournamentRepository";
import dayjs from "dayjs";
import roundRepository from "lib/api/repository/RoundRepository";
import AddParticipantTournamentPageSection from "./AddParticipantTournamentPageSection";
import {useAuthenticatedUser} from "contexts/AuthenticatedUserContext";
import useLoginPageLink from "lib/react/hooks/useLoginPageLink";
import MyActiveTournamentPane from "../MainPage/MyActiveTournamentPane";
import QrCode from "components/QrCode";
import {IoMdShare} from "react-icons/io";
import {usePageTitle} from "lib/react/hooks/usePageTitle";
import {DEFAULT_DATETIME_FORMAT} from "../../lib/api/dto/MainPageData";

function TournamentPage(
    {
        tab = undefined
    }: {
        tab?: "SHARE" | undefined
    }
) {
    let loc = useLoc()
    let loginPageLink = useLoginPageLink();
    let {id, roundId: roundIdStr} = useParams();
    let roundId = useMemo(() => roundIdStr ? parseInt(roundIdStr) : null, [roundIdStr]);
    let tournamentQuery = useQuery({
        queryKey: ["tournamentPageData", id],
        queryFn: () => id ? tournamentPageRepository.getData(id) : Promise.reject<TournamentPageData>()
    })
    let isMain = !roundId && !tab

    usePageTitle(`${tournamentQuery.data?.tournament?.name || "Unnamed"} - ${dayjs(tournamentQuery?.data?.tournament?.date, DEFAULT_DATETIME_FORMAT).format("DD.MM.YYYY")} - Tournament - ChessGrinder`, [tournamentQuery.data])

    let [authenticatedUser] = useAuthenticatedUser()
    let isAuthenticatedUser = !!authenticatedUser

    let meParticipantQuery = useQuery({
        queryKey: ["meParticipant", id],
        queryFn: async () => {
            if (id == null) {
                return null;
            }

            return await participantRepository.getMe(id)
                .catch(() => null);
        }
    })

    let {data: tournamentData} = tournamentQuery;

    let isMeModerator = usePermissionGranted(id || "", "TournamentEntity", "MODERATOR");

    let navigate = useNavigate()
    let roundNumbers = tournamentQuery.data?.rounds?.map((e, idx) => idx + 1) || [];
    let participants: ParticipantDto[] = tournamentQuery.data?.participants || [];

    // If current tab is a round (not main tab and not share tab) and is not finished yet.
    let isCurrentTabIsActiveRound = !!roundId && (tournamentData?.rounds[roundId - 1]?.isFinished === false);

    async function addParticipant(participant: ParticipantDto) {
        await participantRepository.postParticipant(id!!, participant)
            .catch(e => alert("Could not add participant. " +
                e?.response?.data?.message))
        await tournamentQuery.refetch()
    }

    async function openParticipant(participant: ParticipantDto) {
        navigate(`/tournament/${id}/participant/${participant.id}`)
    }

    async function createRound() {
        try {
            await roundRepository.postRound(id!!)
            await tournamentQuery.refetch();
            let newRoundSubPath = tournamentData && tournamentData.rounds ? `/round/${tournamentData.rounds.length + 1}` : "";
            navigate(`/tournament/${id}${newRoundSubPath}`, {replace: true});
        } catch (e: any) {
            alert("Could not create round. " +
                e?.response?.data?.message);
        }
    }

    async function runPairingForRound() {
        await roundRepository.runPairing(id!!, roundId!!)
            .catch(e => alert("Pairing failed! " +
                e?.response?.data?.message));
        await tournamentQuery.refetch()
    }

    async function submitMatchResult(match: MatchDto, result: MatchResult) {
        await roundRepository.postMatchResult(id!!, roundId!!, match.id, result)
            .catch(e => alert("Could not set match result. " +
                e?.response?.data?.message));

        await tournamentQuery.refetch()
    }

    async function deleteRound() {
        await roundRepository.deleteRound(id!!, roundId!!)
            .catch(e => alert(loc("Could not delete round. " +
                e?.response?.data?.message)))
        await tournamentQuery.refetch()
        navigate(`/tournament/${id}`)
    }

    async function finishRound() {
        await roundRepository.finishRound(id!!, roundId!!)
            .catch(e => alert("Could not finish round. Please, check if all match results are submitted. " +
                e?.response?.data?.message))
        await tournamentQuery.refetch()
    }

    async function reopenRound() {
        await roundRepository.reopenRound(id!!, roundId!!)
            .catch(e => alert("Could not reopen round. " +
                e?.response?.data?.message))
        await tournamentQuery.refetch();
    }

    async function copyNicknamesToClipboard() {
        const allNicknames: string = participants
            .filter(participant => !participant.isMissing || participant.score > 0)
            .map(p => p.name)
            .join("\n");
        await copyToClipboard(allNicknames === '' ? ' ' : allNicknames);
        alert(loc('Nicknames have been copied to clipboard'));
    }

    async function copyToClipboard(textToCopy: string) {
        // method for old browsers (and without exceptions handling)
        const textArea = document.createElement('textarea');
        textArea.value = textToCopy;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
    }

    if (tournamentQuery.isError) return <>Error!</>
    if (!tournamentQuery.isSuccess || !tournamentQuery.data) return <>Loading</>
    let tournament = tournamentQuery.data.tournament
    let hideParticipateButton = !meParticipantQuery.isSuccess || !!meParticipantQuery.data

    return <>
        <div className={"flex mt-4 p-2 items-top content-center"}>
            <h2 className={"text-lg font-semibold text-left grow"}>
                {tournament.name || loc(`Unnamed Tournament`)}
            </h2>
            <div className={"px-2"}>
                <div>
                    <small className={"font-semibold text-gray-500"}>{tournament?.status}</small>
                </div>
                <div>
                    <span className={"font-semibold"}>{tournament?.date && dayjs(tournament.date).format("DD.MM.YY")}</span>
                </div>
            </div>
        </div>
        {tournament.status === "ACTIVE" && !meParticipantQuery.data?.isMissing && (isMain || isCurrentTabIsActiveRound) && (
            <MyActiveTournamentPane tournamentId={tournament.id}/>
        )}
        <div className={"flex flex-wrap text-sm justify-start place-items-stretch w-full px-2 my-4"}>
            <Link className={"lg:col-span-1"} to={`/tournament/${id}`} replace={true}>
                <button
                    className={`w-full h-full py-1 px-3 border border-black uppercase ${isMain ? "bg-primary-400 text-white" : "hover:bg-gray-300 text-black"}`}
                    title={loc("Tournament page")}
                >
                    <AiOutlineHome/>
                </button>
            </Link>
            {roundNumbers.map(rid => {
                return <Link
                    to={`/tournament/${id}/round/${rid}`} title={loc(`Open round`) + " " + rid}
                    key={rid}
                    replace={!!roundId} // Write history only if navigating from home page
                >
                    <div
                        className={`w-full py-1 px-3  border border-black
                                    ${rid === roundId ? "bg-primary-400 text-white" : "hover:bg-gray-300"}`}>
                        {rid}
                    </div>
                </Link>
            })}
            <Conditional on={tournament.status !== "FINISHED"}>
                <Conditional on={isMeModerator}>
                    <button className={`py-1 px-3`}
                            onClick={createRound}
                            title={loc("New round")}
                    ><AiOutlinePlus/>
                    </button>
                </Conditional>
            </Conditional>
            <div className={"grow"}></div>
            <Link to={`/tournament/${id}/share`} title={loc("Share")}>
                <button className={"w-full h-full py-1 px-3"}><IoMdShare/></button>
            </Link>
        </div>
        <>
            <Conditional on={isMain}>
                <>
                    {!hideParticipateButton && tournamentData?.tournament?.status === "PLANNED" && (
                        <div className={"px-2"}>
                            {isAuthenticatedUser ?
                                (
                                    <button className={"btn-primary w-full uppercase"}
                                            onClick={async () => {
                                                let nickname = prompt("Please enter your nickname");
                                                if (!nickname) {
                                                    alert("Nickname is not provided. Registration is cancelled.")
                                                } else {
                                                    await tournamentRepository.participate(tournament.id, nickname)
                                                        .catch(() => alert("Could not participate in tournament"));
                                                    await meParticipantQuery.refetch()
                                                    await tournamentQuery.refetch()
                                                }
                                            }}
                                    >
                                        {loc("Participate")}
                                    </button>
                                ) : (
                                    <Link to={loginPageLink} className={"w-full"}>
                                        <button className={"btn-primary w-full uppercase"}>
                                            {loc("Participate")}
                                        </button>
                                    </Link>
                                )
                            }

                        </div>
                    )}
                </>
                <Conditional on={isMeModerator}>
                    <Conditional on={tournamentQuery.data?.tournament?.status !== "FINISHED"}>
                        <AddParticipantTournamentPageSection participants={participants} addParticipant={addParticipant}/>
                    </Conditional>
                </Conditional>
                <div className={"p-2"}>{/*Just padding*/}</div>
                <ResultsTable participants={participants}
                              openParticipant={async (it) => {
                                  await openParticipant(it)
                              }}
                />
            </Conditional>
            <Conditional on={!!roundId}>
                <div className={"p-2"}>
                    <RoundTab
                        tournamentId={tournament.id}
                        round={tournamentData?.rounds[roundId!! - 1]!!}
                        submitMatchResult={(match, result) => submitMatchResult(match, result!!)}
                        submitRoundFinished={() => finishRound()}
                        deleteRound={() => deleteRound()}
                        runPairing={() => runPairingForRound()}
                        reopenRound={() => reopenRound()}
                    />
                </div>
            </Conditional>
            <Conditional on={tab === "SHARE"}>
                <div className={"w-full p-1 grid justify-items-center"}>
                    <div className={"w-1/2 md:w-1/3 lg:w-1/4"}>
                        <QrCode text={(new URL(`/tournament/${tournament.id}`, document.location.href)).href}></QrCode>
                    </div>
                </div>
            </Conditional>
        </>
        <Conditional on={isMain}>
            <Conditional on={isMeModerator}>
                <div className={"flex p-2 items-top content-center"}>
                    <div className={"flex gap-1 justify-start p-2 grow"}>
                        <button className={"btn-light h-full !px-4"}
                            onClick={copyNicknamesToClipboard}
                        >
                            <AiOutlineCopy/>
                        </button>
                    </div>

                    <div className={"flex gap-1 justify-end p-2"}>
                        <Conditional on={tournament.status !== "ACTIVE"}>
                            <button className={"btn-primary uppercase !px-4"}
                                    onClick={async () => {
                                        await tournamentRepository.startTournament(tournament?.id!!)
                                            .catch(e => alert("Could not start tournament. " +
                                                (e?.response?.data?.message || "Unknown error")));
                                        await tournamentQuery.refetch()
                                    }}
                            >{loc("Start")}
                            </button>
                        </Conditional>
                        <Conditional on={tournament.status === "ACTIVE"}>
                            <button className={"btn-primary uppercase"}
                                    onClick={async () => {
                                        await tournamentRepository.finishTournament(tournament?.id!!)
                                            .catch(e => alert("Could not finish tournament. " +
                                                (e?.response?.data?.message || "Unknown error")));
                                        await tournamentQuery.refetch()
                                    }}
                            >{loc("Finish")}
                            </button>
                        </Conditional>
                        <Link to={`/tournament/${tournament.id}/edit`}>
                            <button className={"btn-light h-full !px-4"}>
                                <AiOutlineEdit/>
                            </button>
                        </Link>
                        <button className={"btn-danger uppercase !px-4"}
                                onClick={async () => {
                                    let expectedConfirmation = (tournament?.name || "DELETE");
                                    let confirmation = prompt(`Are you sure?\nTo delete tournament enter \n${expectedConfirmation}`);
                                    if (confirmation !== expectedConfirmation) {
                                        alert("You entered wrong id. Tournament will not be deleted.");
                                        return;
                                    }
                                    await tournamentRepository.deleteTournament(tournament?.id!!)
                                        .catch(e => alert("Could not delete tournament. " +
                                            (e?.response?.data?.message || "Unknown error")));
                                    await navigate("/");
                                }}
                        >
                            <AiOutlineDelete/>
                        </button>
                    </div>
                </div>
            </Conditional>
        </Conditional>
    </>
}

export default TournamentPage;
