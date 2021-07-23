//hi there

package control

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	"github.com/gorilla/mux"
	"github.com/op/go-logging"
	"github.com/tikivn/kr/common/persistance"
	"github.com/tikivn/kr/common/protocol"
	"github.com/tikivn/kr/common/socket"
	"github.com/tikivn/kr/common/transport"
	"github.com/tikivn/kr/common/util"
	"github.com/tikivn/kr/common/version"
	"github.com/tikivn/kr/daemon/enclave"
	"github.com/tikivn/krs/middleware"
	"github.com/tikivn/krs/utils"
)

type ControlServer struct {
	enclaveClient enclave.EnclaveClientI
	timerEngine   TimerEngine
	log           *logging.Logger
	m             middleware.Middleware
}

func NewControlServer(log *logging.Logger, notifier *socket.Notifier) (cs *ControlServer, err error) {
	timerEngine, err := NewTimerEngine()
	if err != nil {
		return
	}

	krdir, err := socket.KrDir()
	if err != nil {
		return
	}
	cs = &ControlServer{enclave.UnpairedEnclaveClient(
		transport.FirebaseTransport{},
		persistance.FilePersister{
			PairingDir: krdir,
			SSHDir:     filepath.Join(socket.HomeDir(), ".ssh"),
		},
		nil,
		log,
		notifier,
	),
		timerEngine,
		log,
		middleware.NewMiddleware(log),
	}
	return
}

func (cs *ControlServer) HandleControlHTTP() (err error) {
	router := mux.NewRouter()

	subVersion := router.NewRoute().Subrouter()
	subVersion.HandleFunc("/version", cs.handleVersion)

	subPair := router.NewRoute().Subrouter()
	subPair.Use(cs.m.AuthorizeJWT)
	subPair.HandleFunc("/pair", cs.handlePair)

	subEnclave := router.NewRoute().Subrouter()
	subEnclave.Use(cs.m.AuthorizeJWT)
	subEnclave.HandleFunc("/enclave", cs.handleEnclave)

	subPing := router.NewRoute().Subrouter()
	subPing.Use(cs.m.AuthorizeJWT)
	subPing.HandleFunc("/ping", cs.handlePing)

	subDevices := router.NewRoute().Subrouter()
	subDevices.Use(cs.m.AuthorizeJWT)
	subDevices.HandleFunc("/devices", cs.handleGetDevices)

	subCheckIn := router.NewRoute().Subrouter()
	subCheckIn.Use(cs.m.AuthorizeJWT)
	subCheckIn.HandleFunc("/checkin/{wsid}", cs.handleCheckIn)

	subHealth := router.NewRoute().Subrouter()
	subHealth.HandleFunc("/health", cs.handleHealth)

	subAdmin := router.NewRoute().PathPrefix("/admin").Subrouter()
	subAdmin.Use(cs.m.AuthorizeJWTAdmin) // OPA for admin
	subAdmin.HandleFunc("/users", cs.handleGetAllUsers)
	subAdmin.HandleFunc("/device", cs.handleAdminGetDevices)
	subAdmin.HandleFunc("/unpair", cs.handleUnpair)

	err = http.ListenAndServe(":8080", router)
	return
}

func (cs *ControlServer) Start() (err error) {
	return cs.enclaveClient.Start()
}

func (cs *ControlServer) Stop() (err error) {
	return cs.enclaveClient.Stop()
}

func (cs *ControlServer) EnclaveClient() enclave.EnclaveClientI {
	return cs.enclaveClient
}

func (cs *ControlServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(version.CURRENT_VERSION.String()))
}

func (cs *ControlServer) handlePair(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cs.handleGetPair(w, r)
		return
	case http.MethodPut:
		cs.handlePutPair(w, r)
		return
	case http.MethodDelete:
		cs.handleDeletePair(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (cs *ControlServer) handleDeletePair(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handleDeletePair")
	wsid := r.URL.Query().Get("wsid")

	cs.enclaveClient.Unpair(wsid, r.Header.Get("Kratos-User"))
	w.WriteHeader(http.StatusOK)
	return
}

//	check if pairing completed
func (cs *ControlServer) handleGetPair(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handleGetPair")
	wsid := r.URL.Query().Get("wsid")

	var meRequest protocol.MeRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&meRequest); err != nil {
			cs.log.Error(err)
		}
	}

	fmt.Println(meRequest)
	meResponse, err := cs.enclaveClient.RequestMe(&meRequest, true, wsid, r.Header.Get("Kratos-User"), true)
	if err == nil && meResponse != nil {
		err = json.NewEncoder(w).Encode(meResponse.Me)
		if err != nil {
			cs.log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("krs encode meResponse fail"))
			return
		}
	} else {
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte("krs not found any devices matched"))
		if err != nil {
			cs.log.Error(err)
		}
		return
	}
}

//	initiate new pairing (clearing any existing)
func (cs *ControlServer) handlePutPair(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handlePutPair")
	var paringOptions protocol.PairingOptions
	err := json.NewDecoder(r.Body).Decode(&paringOptions)
	if err != nil {
		utils.LogDB(r, "pair", false, err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("krs can't decode body content"))
		return
	}

	wsid := fmt.Sprintf("%x", sha1.Sum([]byte(paringOptions.Uuid+paringOptions.WsUser)))

	if cs.EnclaveClient().IsPaired(wsid, r.Header.Get("Kratos-User")) {
		w.WriteHeader(http.StatusOK)
		return
	}

	pairingSecret, err := cs.enclaveClient.Pair(&paringOptions, r.Header.Get("Kratos-User"))
	if err != nil {
		utils.LogDB(r, "pair", false, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("krs got errors while pairing"))
		cs.log.Error(err)
		return
	}
	err = json.NewEncoder(w).Encode(pairingSecret)
	if err != nil {
		utils.LogDB(r, "pair", false, err.Error())
		cs.log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("krs encode pairingSecret fail"))
		return
	}

	utils.LogDB(r, "pair", true, err.Error())
}

//	route request to enclave
func (cs *ControlServer) handleEnclave(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handleEnclave")
	wsid := r.URL.Query().Get("wsid")

	// add LastActive
	cs.enclaveClient.LastActive(wsid, r.Header.Get("Kratos-User"))

	var enclaveRequest protocol.Request
	if err := json.NewDecoder(r.Body).Decode(&enclaveRequest); err != nil {
		utils.LogDB(r, "pair", false, err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if enclaveRequest.MeRequest != nil {
		utils.LogDB(r, "pair", true, "")
		cs.handleEnclaveMe(w, &enclaveRequest, wsid, r.Header.Get("Kratos-User"))
		return
	}

	if enclaveRequest.SignRequest != nil ||
		enclaveRequest.GitSignRequest != nil ||
		enclaveRequest.HostsRequest != nil {
		cs.handleEnclaveGeneric(w, &enclaveRequest, wsid, r.Header.Get("Kratos-User"))
		return
	}

	cs.enclaveClient.RequestNoOp(wsid, r.Header.Get("Kratos-User"))

	w.WriteHeader(http.StatusOK)
}

func (cs *ControlServer) handleEnclaveMe(w http.ResponseWriter, enclaveRequest *protocol.Request, wsid string, kratosUser string) {
	var me util.Profile
	cachedMe := cs.enclaveClient.GetCachedMe(wsid, kratosUser)
	if cachedMe != nil {
		me = *cachedMe
	} else {
		var meRequest protocol.MeRequest
		if enclaveRequest.MeRequest != nil {
			meRequest = *enclaveRequest.MeRequest
		}
		meResponse, err := cs.enclaveClient.RequestMe(&meRequest, false, wsid, kratosUser, true)
		if err != nil {
			cs.log.Error("me request error:", err)
			switch err {
			case util.ErrNotPaired:
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(err.Error()))
			default:
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
			}
			return
		}
		if meResponse != nil {
			me = meResponse.Me
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	response := protocol.Response{
		MeResponse: &protocol.MeResponse{
			Me: me,
		},
	}
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		cs.log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
}

type U2FResult struct {
	IsAllow  bool   `json:"is_allow"`
	StrError string `json:"err"`
}

func (cs *ControlServer) handleEnclaveGeneric(w http.ResponseWriter, enclaveRequest *protocol.Request, wsid string, kratosUser string) {
	if cs.timerEngine.IsExpiredTime(kratosUser, wsid, enclaveRequest.SignRequest.HostAuth.HostNames[0]) {
		response, err := cs.enclaveClient.RequestGeneric(enclaveRequest, nil, wsid, kratosUser, false)
		if err != nil {
			cs.log.Error("request error:", err)
			fmt.Println("request error:", err)
			switch err {
			case util.ErrNotPaired:
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(err.Error()))
			case util.ErrTimedOut:
				w.WriteHeader(http.StatusRequestTimeout)
				w.Write([]byte(err.Error()))
			default:
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
			}
			return
		}

		if signResponse := response.SignResponse; signResponse != nil {
			var result *U2FResult = nil
			if signResponse.Signature != nil {
				digest := sha256.Sum256(enclaveRequest.SignRequest.Data)
				if err := rsa.VerifyPKCS1v15(signResponse.PubKey, crypto.SHA256, digest[:], *signResponse.Signature); err != nil {
					log.Println("Can't verify signature. Error:", err)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintln("Can't verify signature. Error:", err)))
					return
				}

				if signResponse.TypeApprove == 1 {
					cs.timerEngine.AddExpiredTimeThisHost(kratosUser, wsid, enclaveRequest.SignRequest.HostAuth.HostNames[0])
				} else if signResponse.TypeApprove == 2 {
					cs.timerEngine.AddExpiredTimeAllHost(kratosUser, wsid)
				}

				result = &U2FResult{
					IsAllow: true,
				}
			} else if *signResponse.Error == "rejected" {
				result = &U2FResult{
					IsAllow:  false,
					StrError: util.ErrRejected.Error(),
				}
			} else {
				result = &U2FResult{
					IsAllow:  false,
					StrError: util.ErrSigning.Error(),
				}
			}

			if err := json.NewEncoder(w).Encode(result); err != nil {
				cs.log.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				return
			}
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("SignResponse is null"))
			return
		}
	} else {
		go cs.enclaveClient.RequestGeneric(enclaveRequest, nil, wsid, kratosUser, true)
		if err := json.NewEncoder(w).Encode(U2FResult{
			IsAllow: true,
		}); err != nil {
			cs.log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
	}
}

func (cs *ControlServer) handlePing(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (cs *ControlServer) notify(prefix, body string) {
	n, err := socket.OpenNotifier(prefix)
	if err != nil {
		cs.log.Error("error writing notification")
		return
	}
	defer n.Close()
	err = n.Notify(append([]byte(body), '\r', '\n'))
	if err != nil {
		cs.log.Error("error writing notification")
		return
	}
}

/*func (cs *ControlServer) handleGetCachedMe(w http.ResponseWriter, r *http.Request) {
	wsid := r.URL.Query().Get("wsid")

	kratosToken, err := r.Cookie("ory_kratos_session")
	if err != nil {
		log.Println("Get cookie failed. Error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	kratosUser, err := getUserFromKratosToken(kratosToken.Value)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Get user from kratos error " + err.Error()))
		return
	}

	cachedProfile := cs.EnclaveClient().GetCachedMe(wsid, *kratosUser)
	if cachedProfile != nil {
		if err := json.NewEncoder(w).Encode(cachedProfile); err != nil {
			cs.log.Error("Encode failed. Error:", err)
			return
		}
	}
}

func (cs *ControlServer) handleGetTrackingID(w http.ResponseWriter, r *http.Request) {
	wsid := r.URL.Query().Get("wsid")

	kratosToken, err := r.Cookie("ory_kratos_session")
	if err != nil {
		log.Println("Get cookie failed. Error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	kratosUser, err := getUserFromKratosToken(kratosToken.Value)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Get user from kratos error " + err.Error()))
		return
	}

	pairingSecret := cs.EnclaveClient().GetPairingSecret(wsid, *kratosUser)
	if pairingSecret != nil {
		tID := pairingSecret.TrackingID
		if err := json.NewEncoder(w).Encode(tID); err != nil {
			cs.log.Error("Encode failed. Error:", err)
			return
		}
	}
}*/

func (cs *ControlServer) handleGetDevices(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handleGetDevices")
	mDevices := cs.enclaveClient.GetDevices(r.Header.Get("Kratos-User"))
	if err := json.NewEncoder(w).Encode(mDevices); err != nil {
		cs.log.Error("Encode failed. Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("krs encode devices fail"))
		return
	}
}

func (cs *ControlServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (cs *ControlServer) handleCheckIn(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handleCheckIn")
	params := mux.Vars(r)
	wsid := params["wsid"]
	// add LastActive for browser
	err := cs.enclaveClient.LastActive(wsid, r.Header.Get("Kratos-User"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprint("error when set last acttive", err)))
		return
	}

	w.WriteHeader(http.StatusOK)
	return
}

func (cs *ControlServer) handleGetAllUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handleGetAllUsers")
	allUsers := cs.enclaveClient.GetAllUsers()
	if err := json.NewEncoder(w).Encode(allUsers); err != nil {
		cs.log.Error("Encode failed. Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("krs encode all users fail"))
		return
	}
}

func (cs *ControlServer) handleAdminGetDevices(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handleAdminGetDevices")
	mDevices := cs.enclaveClient.GetDevices(r.URL.Query().Get("username"))
	if err := json.NewEncoder(w).Encode(mDevices); err != nil {
		cs.log.Error("Encode failed. Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("krs encode devices fail"))
		return
	}
}

func (cs *ControlServer) handleUnpair(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handleUnpair")
	username := r.URL.Query().Get("username")
	wsid := r.URL.Query().Get("wsid")

	cs.enclaveClient.Unpair(wsid, username)
	w.WriteHeader(http.StatusOK)
	return
}
