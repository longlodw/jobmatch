package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/grokify/go-pkce"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
)

type IOAuth interface {
	Initiate(scopes []string) (authUrl, state, codeVerifier string, err error)
	Exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error)
	VerifyIDToken(ctx context.Context, idToken string) (*oidc.IDToken, error)
	Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error)
}

type IDrive interface {
	CreateFolderIfNotExists(ctx context.Context, folderName string, parentFolderID string) (string, error)
	CopyFile(ctx context.Context, fileId, parentFolderId string) (string, error)
	ExportDocsAsText(ctx context.Context, fileId string) (string, error)
	LastModifiedTime(ctx context.Context, fileId string) (time.Time, error)
	CreateSheetIfNotExists(ctx context.Context, sheetName string, parentFolderID string) (string, error)
	InsertRows(ctx context.Context, sheetId string, values [][]any) error
	GetFileLink(fileId string) string
}

type GoogleOAuth struct {
	clientID     string
	clientSecret string
	redirectURL  string
	ocidProvider *oidc.Provider
}

func NewGoogleOAuth(ctx context.Context, clientID, clientSecret, redirectURL string) (*GoogleOAuth, error) {
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, err
	}
	return &GoogleOAuth{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		ocidProvider: provider,
	}, nil
}

func (g *GoogleOAuth) Initiate(scopes []string) (authUrl, state, codeVerifier string, err error) {
	config := &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecret,
		RedirectURL:  g.redirectURL,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
	}
	codeVerifier, codeChallenge, err := generateCodePair()
	if err != nil {
		return
	}
	state = uuid.New().String()
	authUrl = config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	return
}

func (g *GoogleOAuth) Exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecret,
		RedirectURL:  g.redirectURL,
		Endpoint:     google.Endpoint,
	}
	token, err := config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (g *GoogleOAuth) VerifyIDToken(ctx context.Context, idToken string) (*oidc.IDToken, error) {
	verifier := g.ocidProvider.Verifier(&oidc.Config{ClientID: g.clientID})
	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (g *GoogleOAuth) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecret,
		RedirectURL:  g.redirectURL,
		Endpoint:     google.Endpoint,
	}
	tokSrc := config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	newToken, err := tokSrc.Token()
	if err != nil {
		return nil, err
	}
	return newToken, nil
}

func ExtractIDToken(token *oauth2.Token) (string, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("no id_token field in oauth2 token")
	}
	return rawIDToken, nil
}

type GoogleDrive struct {
	driveService  *drive.Service
	sheetsService *sheets.Service
}

func NewGoogleDrive(ctx context.Context, oauthToken *oauth2.Token) (*GoogleDrive, error) {
	ts := oauth2.StaticTokenSource(oauthToken)
	driveSrv, err := drive.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		return nil, err
	}
	sheetsSrv, err := sheets.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		return nil, err
	}
	return &GoogleDrive{
		driveService:  driveSrv,
		sheetsService: sheetsSrv,
	}, nil
}

func (g *GoogleDrive) CreateFolderIfNotExists(ctx context.Context, folderName string, parentFolderID string) (string, error) {
	query := "mimeType='application/vnd.google-apps.folder' and name='" + folderName + "' and trashed=false"
	if parentFolderID != "" {
		query += " and '" + parentFolderID + "' in parents"
	}
	r, err := g.driveService.Files.List().Q(query).Fields("files(id, name)").Do()
	if err != nil {
		return "", err
	}
	if len(r.Files) > 0 {
		return r.Files[0].Id, nil
	}
	folder := &drive.File{
		Name:     folderName,
		MimeType: "application/vnd.google-apps.folder",
	}
	if parentFolderID != "" {
		folder.Parents = []string{parentFolderID}
	}
	createdFolder, err := g.driveService.Files.Create(folder).Fields("id").Do()
	if err != nil {
		return "", err
	}
	return createdFolder.Id, nil
}

func (g *GoogleDrive) CopyFile(ctx context.Context, fileId, parentFolderId string) (string, error) {
	newFile := &drive.File{}
	if parentFolderId != "" {
		newFile.Parents = []string{parentFolderId}
	}
	copiedFile, err := g.driveService.Files.Copy(fileId, newFile).Fields("id").Do()
	if err != nil {
		return "", err
	}
	return copiedFile.Id, nil
}

func (g *GoogleDrive) ExportDocsAsText(ctx context.Context, fileId string) (string, error) {
	resp, err := g.driveService.Files.Export(fileId, "text/plain").Download()
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := &strings.Builder{}
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (g *GoogleDrive) LastModifiedTime(ctx context.Context, fileId string) (time.Time, error) {
	file, err := g.driveService.Files.Get(fileId).Fields("modifiedTime").Do()
	if err != nil {
		return time.Time{}, err
	}
	modifiedTime, err := time.Parse(time.RFC3339, file.ModifiedTime)
	if err != nil {
		return time.Time{}, err
	}
	return modifiedTime, nil
}

func (g *GoogleDrive) CreateSheetIfNotExists(ctx context.Context, sheetName string, parentFolderID string) (string, error) {
	query := "mimeType='application/vnd.google-apps.spreadsheet' and name='" + sheetName + "' and trashed=false"
	if parentFolderID != "" {
		query += " and '" + parentFolderID + "' in parents"
	}
	r, err := g.driveService.Files.List().Q(query).Fields("files(id, name)").Do()
	if err != nil {
		return "", err
	}
	if len(r.Files) > 0 {
		return r.Files[0].Id, nil
	}
	sheet := &drive.File{
		Name:     sheetName,
		MimeType: "application/vnd.google-apps.spreadsheet",
	}
	if parentFolderID != "" {
		sheet.Parents = []string{parentFolderID}
	}
	createdSheet, err := g.driveService.Files.Create(sheet).Fields("id").Do()
	if err != nil {
		return "", err
	}
	return createdSheet.Id, nil
}

func (g *GoogleDrive) InsertRows(ctx context.Context, sheetId string, values [][]any) error {
	srv := g.sheetsService
	valueRange := &sheets.ValueRange{
		Values: values,
	}
	_, err := srv.Spreadsheets.Values.Append(sheetId, "Sheet1", valueRange).ValueInputOption("RAW").InsertDataOption("INSERT_ROWS").Do()
	if err != nil {
		return err
	}
	return nil
}

func (g *GoogleDrive) GetFileLink(fileId string) string {
	return "https://drive.google.com/file/d/" + fileId + "/view"
}

func generateCodePair() (string, string, error) {
	codeVerifier, err := pkce.NewCodeVerifier(64)
	if err != nil {
		return "", "", err
	}
	codeChallenge := pkce.CodeChallengeS256(codeVerifier)
	return codeVerifier, codeChallenge, nil
}
