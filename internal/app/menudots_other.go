//go:build !darwin

package app

type menuDots struct{}

func (a *App) watchMenuDots() {}

func (a *App) setMenuDots() {}
