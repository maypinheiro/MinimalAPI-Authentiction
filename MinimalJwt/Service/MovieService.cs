﻿using MinimalJwt.Models;
using MinimalJwt.Repositories;

namespace MinimalJwt.Service
{
    public class MovieService : IMovieService
    {
        public Movie Create(Movie movie)
        {
            movie.Id = MovieRepository.Movies.Count + 1; 
            MovieRepository.Movies.Add(movie);  
            return movie;
        }

        public bool Delete(int id)
        {
            var oldMovie = MovieRepository.Movies.FirstOrDefault(x => x.Id == id);
            if (oldMovie is null) return false;
            MovieRepository.Movies.Remove(oldMovie);
            return true;

        }

        public Movie Get(int id)
        {
           var movie = MovieRepository.Movies.FirstOrDefault(x => x.Id == id);
           if(movie is null) return null;
           return movie;
        }

        public List<Movie> GetAll()
        {
            var movies = MovieRepository.Movies;
            return movies;
        }

        public Movie Update(Movie newMovie)
        {
            var oldMovie = MovieRepository.Movies.FirstOrDefault(x => x.Id == newMovie.Id);
            if(oldMovie is null) return null;

            oldMovie.Title = newMovie.Title;
            oldMovie.Description= newMovie.Description;
            oldMovie.Rating = newMovie.Rating;
            return  oldMovie;
        }
    }
}
